#include "esphome/core/defines.h"
#ifdef USE_MATTER

#include "esphome/components/network/util.h"
#ifdef USE_OPENTHREAD
#include "esphome/components/openthread/openthread.h"
#endif // USE_OPENTHREAD
#ifdef USE_WIFI
#include <esp_wifi.h>
#include "esphome/components/wifi/wifi_component.h"
#include <platform/ESP32/NetworkCommissioningDriver.h>
#endif // USE_WIFI
#include "esphome/core/application.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "matter_component.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <esp_matter_client.h>
#include <esp_matter_cluster.h>
#include <esp_random.h>
#include <nvs.h>
#include <string>

#include <app/server/Server.h>
#include <app/server/Dnssd.h>
#include <crypto/CHIPCryptoPAL.h>
#if CHIP_DEVICE_CONFIG_ENABLE_THREAD
#include <platform/ESP32/ThreadStackManagerImpl.h>
#endif // CHIP_DEVICE_CONFIG_ENABLE_THREAD
#include <lib/support/Base64.h>
#ifdef USE_OPENTHREAD
#include <openthread/ip6.h>
#endif // USE_OPENTHREAD
#include <setup_payload/ManualSetupPayloadGenerator.h>
#include <setup_payload/QRCodeSetupPayloadGenerator.h>
#include <setup_payload/SetupPayload.h>

static const char *const TAG = "matter";
static const char *const TAG_EVENT = "matter.event";

// Keys in the "chip-factory" NVS namespace, matching CHIP's ESP32Config key
// names.
static constexpr const char *NVS_NAMESPACE = "chip-factory";
static constexpr const char *NVS_KEY_DISCRIMINATOR = "discriminator";
static constexpr const char *NVS_KEY_PASSCODE = "pin-code";
static constexpr const char *NVS_KEY_ITERATION_COUNT = "iteration-count";
static constexpr const char *NVS_KEY_SALT = "salt";
static constexpr const char *NVS_KEY_VERIFIER = "verifier";

static constexpr uint32_t SPAKE2P_ITERATION_COUNT = 1000;
static constexpr size_t SPAKE2P_SALT_LENGTH = 32;

static bool is_valid_passcode(uint32_t pin) {
  if (pin == 0 || pin > 99999998)
    return false;
  static constexpr uint32_t FORBIDDEN[] = {
      11111111, 22222222, 33333333, 44444444, 55555555, 66666666,
      77777777, 88888888, 99999999, 12345678, 87654321,
  };
  for (uint32_t f : FORBIDDEN) {
    if (pin == f)
      return false;
  }
  return true;
}

// Loads existing commissioning data from NVS, or generates random values and
// stores them. The EXAMPLE_COMMISSIONABLE_DATA_PROVIDER reads these same NVS
// keys on every boot, so whatever we write here becomes the device's
// commissioning identity.
static bool load_or_generate_commissioning_data(uint16_t &discriminator,
                                                uint32_t &passcode) {
  nvs_handle_t handle;
  if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS namespace '%s'", NVS_NAMESPACE);
    return false;
  }

  uint32_t stored_discriminator, stored_passcode;
  bool already_provisioned =
      (nvs_get_u32(handle, NVS_KEY_DISCRIMINATOR, &stored_discriminator) ==
           ESP_OK &&
       nvs_get_u32(handle, NVS_KEY_PASSCODE, &stored_passcode) == ESP_OK);
  if (already_provisioned) {
    discriminator = (uint16_t)stored_discriminator;
    passcode = stored_passcode;
    nvs_close(handle);
    return true;
  }

#ifdef MATTER_DISCRIMINATOR
  discriminator = MATTER_DISCRIMINATOR;
#else
  discriminator = (uint16_t)(esp_random() & 0x0FFFu);
#endif // MATTER_DISCRIMINATOR

#ifdef MATTER_PASSCODE
  passcode = MATTER_PASSCODE;
#else
  do {
    passcode = (esp_random() % 99999998u) + 1u;
  } while (!is_valid_passcode(passcode));
#endif // MATTER_PASSCODE

  // Generate random salt using the ESP32 hardware RNG.
  uint8_t salt[SPAKE2P_SALT_LENGTH];
  for (size_t i = 0; i < SPAKE2P_SALT_LENGTH; i += sizeof(uint32_t)) {
    uint32_t r = esp_random();
    size_t bytes = std::min(sizeof(uint32_t), SPAKE2P_SALT_LENGTH - i);
    memcpy(salt + i, &r, bytes);
  }

  // Compute the Spake2p verifier from the passcode + salt + iteration count.
  // Storing the verifier (rather than the raw passcode) means future boots
  // don't need to recompute it, and the factory partition holds a stronger
  // derived secret.
  chip::Crypto::Spake2pVerifier verifier;
  if (verifier.Generate(SPAKE2P_ITERATION_COUNT,
                        chip::ByteSpan(salt, SPAKE2P_SALT_LENGTH),
                        passcode) != CHIP_NO_ERROR) {
    ESP_LOGE(TAG, "Failed to generate Spake2p verifier");
    nvs_close(handle);
    return false;
  }
  uint8_t verifier_bytes[chip::Crypto::kSpake2p_VerifierSerialized_Length];
  chip::MutableByteSpan verifier_span(verifier_bytes, sizeof(verifier_bytes));
  if (verifier.Serialize(verifier_span) != CHIP_NO_ERROR) {
    ESP_LOGE(TAG, "Failed to serialize Spake2p verifier");
    nvs_close(handle);
    return false;
  }

  char salt_b64[BASE64_ENCODED_LEN(SPAKE2P_SALT_LENGTH) + 1];
  salt_b64[chip::Base64Encode32(salt, SPAKE2P_SALT_LENGTH, salt_b64)] = '\0';

  char verifier_b64[BASE64_ENCODED_LEN(
                        chip::Crypto::kSpake2p_VerifierSerialized_Length) +
                    1];
  verifier_b64[chip::Base64Encode32(verifier_bytes, sizeof(verifier_bytes),
                                    verifier_b64)] = '\0';

  nvs_set_u32(handle, NVS_KEY_DISCRIMINATOR, discriminator);
  nvs_set_u32(handle, NVS_KEY_PASSCODE, passcode);
  nvs_set_u32(handle, NVS_KEY_ITERATION_COUNT, SPAKE2P_ITERATION_COUNT);
  nvs_set_str(handle, NVS_KEY_SALT, salt_b64);
  nvs_set_str(handle, NVS_KEY_VERIFIER, verifier_b64);
  nvs_commit(handle);
  nvs_close(handle);

  return true;
}

namespace esphome::matter {

MatterComponent *global_matter_component =
    nullptr; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static void event_callback(const ChipDeviceEvent *event, intptr_t arg) {
  switch (event->Type) {
  case chip::DeviceLayer::DeviceEventType::kInterfaceIpAddressChanged:
    ESP_LOGD(TAG_EVENT, "Interface IP Address changed");
    if (global_matter_component != nullptr) {
      global_matter_component->defer_to_main_loop([]() {
        if (global_matter_component == nullptr)
          return;
        global_matter_component->refresh_operational_advertising();
#ifdef USE_WIFI
        global_matter_component->update_wifi_network_info_();
#endif
      });
    }
    break;
  case chip::DeviceLayer::DeviceEventType::kCommissioningComplete:
    ESP_LOGI(TAG_EVENT, "Commissioning complete");
    break;
  case chip::DeviceLayer::DeviceEventType::kFailSafeTimerExpired:
    ESP_LOGI(TAG_EVENT, "Commissioning failed, fail safe timer expired");
    break;
  case chip::DeviceLayer::DeviceEventType::kCommissioningSessionStarted:
    ESP_LOGI(TAG_EVENT, "Commissioning session started");
    break;
  case chip::DeviceLayer::DeviceEventType::kCommissioningSessionStopped:
    ESP_LOGI(TAG_EVENT, "Commissioning session stopped");
    break;
  case chip::DeviceLayer::DeviceEventType::kCommissioningWindowOpened:
    ESP_LOGI(TAG_EVENT, "Commissioning window opened");
    break;
  case chip::DeviceLayer::DeviceEventType::kCommissioningWindowClosed:
    ESP_LOGI(TAG_EVENT, "Commissioning window closed");
    break;
  case chip::DeviceLayer::DeviceEventType::kFabricRemoved:
    ESP_LOGI(TAG_EVENT, "Fabric removed");
    if (global_matter_component != nullptr) {
#ifdef USE_TEXT_SENSOR
      global_matter_component->schedule_fabric_sensor_update();
#endif
      // If no fabrics remain, open a basic commissioning window so the device
      // can be re-paired without a full factory reset.
      if (chip::Server::GetInstance().GetFabricTable().FabricCount() == 0) {
        ESP_LOGI(TAG_EVENT,
                 "Last fabric removed — opening commissioning window");
        chip::Server::GetInstance()
            .GetCommissioningWindowManager()
            .OpenBasicCommissioningWindow();
      }
    }
    break;
  case chip::DeviceLayer::DeviceEventType::kFabricWillBeRemoved:
    ESP_LOGI(TAG_EVENT, "Fabric will be removed");
    break;
  case chip::DeviceLayer::DeviceEventType::kFabricUpdated:
    ESP_LOGI(TAG_EVENT, "Fabric is updated");
#ifdef USE_TEXT_SENSOR
    if (global_matter_component != nullptr)
      global_matter_component->schedule_fabric_sensor_update();
#endif
    break;
  case chip::DeviceLayer::DeviceEventType::kFabricCommitted:
    ESP_LOGI(TAG_EVENT, "Fabric is committed");
#ifdef USE_TEXT_SENSOR
    if (global_matter_component != nullptr)
      global_matter_component->schedule_fabric_sensor_update();
#endif
    break;
  case chip::DeviceLayer::DeviceEventType::kDnssdRestartNeeded:
    ESP_LOGD(TAG_EVENT, "DNS-SD restart needed");
    if (global_matter_component != nullptr)
      global_matter_component->refresh_operational_advertising();
    break;
  case chip::DeviceLayer::DeviceEventType::kBindingsChangedViaCluster:
    ESP_LOGI(TAG_EVENT, "Bindings updated");
    break;
  case chip::DeviceLayer::DeviceEventType::kServerReady:
    ESP_LOGI(TAG_EVENT, "Server ready!");
    if (global_matter_component != nullptr) {
      // Re-advertise and push Wi-Fi info once the server is fully up. This
      // shortens the post-reboot window where controllers fail discovery.
      global_matter_component->defer_to_main_loop([]() {
        if (global_matter_component == nullptr)
          return;
        global_matter_component->refresh_operational_advertising();
#ifdef USE_WIFI
        global_matter_component->update_wifi_network_info_();
#endif
      });
    }
    break;
  case chip::DeviceLayer::DeviceEventType::kSecureSessionEstablished: {
    const auto &s = event->SecureSessionEstablished;
    ESP_LOGI(TAG_EVENT,
             "Secure session established: %s node=0x%016" PRIx64
             " fabric=%u session=%u",
             s.SecureSessionType == 2   ? "CASE"
             : s.SecureSessionType == 1 ? "PASE"
                                        : "?",
             s.PeerNodeId, s.FabricIndex, s.LocalSessionId);
    break;
  }
  case chip::DeviceLayer::DeviceEventType::kWiFiConnectivityChange: // 0x8000
    ESP_LOGV(TAG_EVENT, "WiFiConnectivityChange");
#ifdef USE_WIFI
    if (global_matter_component != nullptr) {
      global_matter_component->defer_to_main_loop([]() {
        if (global_matter_component != nullptr)
          global_matter_component->update_wifi_network_info_();
      });
    }
#endif
    break;
  case chip::DeviceLayer::DeviceEventType::
      kThreadConnectivityChange: { // 0x8001
    switch (event->ThreadConnectivityChange.Result) {
    case chip::DeviceLayer::kConnectivity_Established:
      ESP_LOGI(TAG_EVENT, "ThreadConnectivityChange: established");
      break;
    case chip::DeviceLayer::kConnectivity_Lost:
      ESP_LOGW(TAG_EVENT, "ThreadConnectivityChange: lost");
      break;
    case chip::DeviceLayer::kConnectivity_NoChange:
      ESP_LOGV(TAG_EVENT, "ThreadConnectivityChange: no_change");
      break;
    default:
      ESP_LOGV(TAG_EVENT, "ThreadConnectivityChange: unknown (%d)",
               static_cast<int>(event->ThreadConnectivityChange.Result));
      break;
    }
    break;
  }
  case chip::DeviceLayer::DeviceEventType::
      kInternetConnectivityChange: // 0x8002
    ESP_LOGV(TAG_EVENT, "InternetConnectivityChange");
    break;
  case chip::DeviceLayer::DeviceEventType::kThreadStateChange: { // 0x800B
#ifdef USE_OPENTHREAD
    const auto &thread_state = event->ThreadStateChange;
    if (thread_state.RoleChanged) {
      auto lock = esphome::openthread::InstanceLock::try_acquire(1000);
      if (lock) {
        const otDeviceRole role = otThreadGetDeviceRole(lock.get_instance());
        ESP_LOGD(TAG_EVENT, "Thread role changed to %s",
                 otThreadDeviceRoleToString(role));
      } else {
        ESP_LOGW(TAG_EVENT, "Thread role changed; unable to acquire instance");
      }
    }
    if (thread_state.NetDataChanged)
      ESP_LOGV(TAG_EVENT, "Thread network data changed");
    if (thread_state.ChildNodesChanged)
      ESP_LOGV(TAG_EVENT, "Thread child nodes changed");
    if (thread_state.AddressChanged) {
      ESP_LOGD(TAG_EVENT, "Thread address(es) changed");
      auto lock = esphome::openthread::InstanceLock::try_acquire(1000);
      if (lock) {
        otInstance *instance = lock.get_instance();
        for (const otNetifAddress *addr = otIp6GetUnicastAddresses(instance);
             addr != nullptr; addr = addr->mNext) {
          char address[OT_IP6_ADDRESS_STRING_SIZE];
          otIp6AddressToString(&addr->mAddress, address, sizeof(address));
          if (addr->mValid)
            ESP_LOGD(TAG_EVENT, "  address %s/%u rloc=%s", address,
                     static_cast<unsigned>(addr->mPrefixLength),
                     YESNO(addr->mRloc));
          else
            ESP_LOGW(TAG_EVENT, "  [INVALID] address %s/%u rloc=%s", address,
                     static_cast<unsigned>(addr->mPrefixLength),
                     YESNO(addr->mRloc));
        }
      } else {
        ESP_LOGW(TAG_EVENT,
                 "ThreadStateChange: address list unavailable; failed to "
                 "acquire OpenThread lock");
      }
    }
    if (!thread_state.RoleChanged && !thread_state.AddressChanged &&
        !thread_state.NetDataChanged && !thread_state.ChildNodesChanged)
      ESP_LOGV(TAG_EVENT, "ThreadStateChange: flags=0x%08" PRIx32,
               thread_state.OpenThread.Flags);
#endif // USE_OPENTHREAD
    break;
  }
  case chip::DeviceLayer::DeviceEventType::kDnssdInitialized: // 0x8012
    ESP_LOGD(TAG_EVENT, "DnssdInitialized");
    break;
  default:
    ESP_LOGV(TAG_EVENT, "0x%04X", event->Type);
    break;
  }
}

void MatterComponent::setup() {
  global_matter_component = this;
  uint16_t discriminator;
  uint32_t passcode;
  if (!load_or_generate_commissioning_data(discriminator, passcode)) {
    this->mark_failed();
    return;
  }
  this->discriminator_ = discriminator;
  this->passcode_ = passcode;
  this->generate_commissioning_codes_();

#ifdef USE_TEXT_SENSOR
  this->publish_commissioning_code_sensors_();
#endif

  char serial_number[33];
#ifdef MATTER_SERIAL_NUMBER
  snprintf(serial_number, sizeof(serial_number), "%s", MATTER_SERIAL_NUMBER);
#else
  uint8_t mac[6];
  get_mac_address_raw(mac);
  snprintf(serial_number, sizeof(serial_number), "%02X%02X%02X%02X%02X%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#endif // MATTER_SERIAL_NUMBER

  // Always update device-name and serial-num so they stay in sync with the
  // ESPHome device name and MAC address. device-name is the DN TXT record in
  // _matterc._udp — what controllers show in their UI; serial-num is read by
  // CHIP's DeviceInstanceInfoProvider for BasicInformation::SerialNumber.
  {
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
      nvs_set_str(h, "device-name", App.get_name().c_str());
      nvs_set_str(h, "serial-num", serial_number);
      nvs_commit(h);
      nvs_close(h);
    }
  }

  esp_matter::node::config_t node_config;
  esp_matter::node_t *node = esp_matter::node::create(
      &node_config, endpoint_attribute_update_cb, nullptr);
  if (node == nullptr) {
    ESP_LOGE(TAG, "Failed to create Matter node");
    this->mark_failed();
    return;
  }

  // Ensure BasicInformation::SerialNumber (optional attribute) is created on
  // endpoint 0 and populated from the device MAC address.
  if (esp_matter::endpoint_t *root_endpoint = esp_matter::endpoint::get(node, 0)) {
    if (esp_matter::cluster_t *basic_info_cluster = esp_matter::cluster::get(
            root_endpoint, chip::app::Clusters::BasicInformation::Id)) {
      if (esp_matter::attribute::get(
              basic_info_cluster,
              chip::app::Clusters::BasicInformation::Attributes::SerialNumber::Id) ==
          nullptr) {
        esp_matter::cluster::basic_information::attribute::create_serial_number(
            basic_info_cluster, serial_number, strlen(serial_number));
      }
    }
  }

  if (!this->create_endpoints_(node)) {
    this->mark_failed();
    return;
  }

#ifdef USE_OPENTHREAD
  // ESPHome owns the OpenThread task/stack. connectedhomeip still needs its
  // ThreadStackManager bound to that existing instance for Thread diagnostics
  // and other Thread helpers.
  if (chip::DeviceLayer::ThreadStackMgrImpl()._AttachToThreadStack() !=
      CHIP_NO_ERROR) {
    ESP_LOGE(TAG, "Failed to attach ESPHome OpenThread stack to "
                  "connectedhomeip ThreadStackManager");
    this->mark_failed();
    return;
  }
#endif // USE_OPENTHREAD

  /* Matter start */
  esp_err_t err = esp_matter::start(event_callback);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start Matter: %s", esp_err_to_name(err));
    this->mark_failed();
    return;
  } else {
    ESP_LOGD(TAG, "Matter started successfully");
  }

#ifdef USE_WIFI
  // Populate Wi-Fi network info for controllers (SSID in device details).
  // Retry a few times — Wi-Fi / attribute store may not be ready immediately.
  this->set_timeout(2000, [this]() { this->update_wifi_network_info_(); });
  this->set_timeout(8000, [this]() { this->update_wifi_network_info_(); });
  this->set_timeout(20000, [this]() { this->update_wifi_network_info_(); });
#endif

#ifdef USE_OPENTHREAD
  // ESPHome owns Thread, so CONFIG_ESP_MATTER_ENABLE_OPENTHREAD is disabled.
  // esp_matter::start() consequently skips advertising existing fabrics.
  // Start the advertiser on the Matter task after its server is initialized;
  // the DNS-SD bridge registers these services with ESPHome's SRP client.
  CHIP_ERROR advertising_error = chip::DeviceLayer::PlatformMgr().ScheduleWork(
      [](intptr_t) { chip::app::DnssdServer::Instance().StartServer(); }, 0);
  if (advertising_error != CHIP_NO_ERROR) {
    ESP_LOGE(TAG,
             "Failed to schedule Thread Matter service advertising: "
             "0x%08" PRIx32,
             static_cast<uint32_t>(advertising_error.AsInteger()));
  } else {
    ESP_LOGD(TAG, "Scheduled Thread Matter operational advertisement");
  }
#endif // USE_OPENTHREAD

  esp_matter::client::binding_manager_init();
  replay_attribute_triggers(this);
  this->initialize_endpoint_mappings_();
#ifdef USE_TEXT_SENSOR
  this->publish_fabric_sensors_();
#endif
}

void MatterComponent::factory_reset() {
  ESP_LOGW(TAG, "Matter factory reset. Erasing fabric data and rebooting");
  for (const char *ns : {"chip-config", "chip-counters", "CHIP_KVS"}) {
    nvs_handle_t h;
    if (nvs_open(ns, NVS_READWRITE, &h) == ESP_OK) {
      nvs_erase_all(h);
      nvs_commit(h);
      nvs_close(h);
    }
  }
  App.safe_reboot();
}

bool MatterComponent::remove_fabric(uint8_t fabric_index) {
  if (fabric_index == 0) {
    ESP_LOGW(TAG, "remove_fabric: fabric_index 0 is invalid");
    return false;
  }

  auto &server = chip::Server::GetInstance();
  auto &fabric_table = server.GetFabricTable();
  auto *info = fabric_table.FindFabricWithIndex(fabric_index);
  if (info == nullptr) {
    ESP_LOGW(TAG, "remove_fabric: no fabric at index %u", fabric_index);
    return false;
  }

  ESP_LOGI(TAG,
           "Removing fabric index %u (VendorId=0x%04X NodeId=0x%08" PRIx32
           "%08" PRIx32 ")",
           fabric_index, (uint16_t)info->GetVendorId(),
           (uint32_t)(info->GetNodeId() >> 32), (uint32_t)info->GetNodeId());

  CHIP_ERROR err = fabric_table.Delete(fabric_index);
  if (err != CHIP_NO_ERROR) {
    ESP_LOGE(TAG, "remove_fabric failed: %" CHIP_ERROR_FORMAT, err.Format());
    return false;
  }

  ESP_LOGI(TAG, "Fabric %u removed (%u remaining)", fabric_index,
           fabric_table.FabricCount());
#ifdef USE_TEXT_SENSOR
  this->schedule_fabric_sensor_update();
#endif
  return true;
}

bool MatterComponent::update_fabric_label(uint8_t fabric_index,
                                          const std::string &label) {
  if (fabric_index == 0) {
    ESP_LOGW(TAG, "update_fabric_label: fabric_index 0 is invalid");
    return false;
  }
  if (label.size() > chip::kFabricLabelMaxLengthInBytes) {
    ESP_LOGW(TAG, "update_fabric_label: label too long (max %u)",
             (unsigned)chip::kFabricLabelMaxLengthInBytes);
    return false;
  }

  auto &fabric_table = chip::Server::GetInstance().GetFabricTable();
  if (fabric_table.FindFabricWithIndex(fabric_index) == nullptr) {
    ESP_LOGW(TAG, "update_fabric_label: no fabric at index %u", fabric_index);
    return false;
  }

  CHIP_ERROR err = fabric_table.SetFabricLabel(
      fabric_index, chip::CharSpan(label.data(), label.size()));
  if (err != CHIP_NO_ERROR) {
    ESP_LOGE(TAG, "SetFabricLabel failed: %" CHIP_ERROR_FORMAT, err.Format());
    return false;
  }

  ESP_LOGI(TAG, "Fabric %u label set to '%s'", fabric_index, label.c_str());
#ifdef USE_TEXT_SENSOR
  this->schedule_fabric_sensor_update();
#endif
  return true;
}

void MatterComponent::refresh_operational_advertising() {
  CHIP_ERROR err = chip::DeviceLayer::PlatformMgr().ScheduleWork(
      [](intptr_t) {
        chip::app::DnssdServer::Instance().StartServer();
        ESP_LOGD("matter", "Operational DNS-SD advertising refreshed");
      },
      0);
  if (err != CHIP_NO_ERROR) {
    ESP_LOGW(TAG, "Failed to schedule DNS-SD refresh: %" CHIP_ERROR_FORMAT,
             err.Format());
  }
}

#ifdef USE_WIFI
void MatterComponent::update_wifi_network_info_() {
  // Use CHIP's own ESP Wi-Fi NetworkCommissioning driver to report status.
  // OnNetworkStatusChange() reads the current AP via esp_wifi_sta_get_ap_info
  // and calls the NetworkCommissioning Instance callback, which correctly
  // populates LastNetworkID / LastNetworkingStatus (attributes that reject
  // direct attribute::update writes).
  wifi_ap_record_t ap_info{};
  if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
    ESP_LOGD(TAG, "update_wifi_network_info_: not connected yet");
    return;
  }

  const char *ssid = reinterpret_cast<const char *>(ap_info.ssid);
  ESP_LOGD(TAG,
           "Updating Matter Wi-Fi info via ESPWiFiDriver: SSID='%s' RSSI=%d ch=%u",
           ssid, ap_info.rssi, ap_info.primary);

  // Must run on the CHIP stack so the status callback can safely update
  // NetworkCommissioning cluster state and trigger attribute reports.
  chip::DeviceLayer::PlatformMgr().ScheduleWork(
      [](intptr_t) {
        chip::DeviceLayer::NetworkCommissioning::ESPWiFiDriver::GetInstance()
            .OnNetworkStatusChange();
      },
      0);
}
#endif // USE_WIFI

void MatterComponent::generate_commissioning_codes_() {
  chip::SetupPayload payload;
  payload.version = 0;
  payload.vendorID = CHIP_DEVICE_CONFIG_DEVICE_VENDOR_ID;
  payload.productID = CHIP_DEVICE_CONFIG_DEVICE_PRODUCT_ID;
  payload.commissioningFlow = chip::CommissioningFlow::kStandard;
#if defined(USE_OPENTHREAD) || defined(USE_WIFI) || defined(USE_ETHERNET)
  payload.rendezvousInformation.SetValue(
      chip::RendezvousInformationFlag::kOnNetwork);
#else
  payload.rendezvousInformation.SetValue(chip::RendezvousInformationFlag::kBLE);
#endif // defined(USE_OPENTHREAD) || defined(USE_WIFI) || defined(USE_ETHERNET)
  payload.discriminator.SetLongValue(this->discriminator_);
  payload.setUpPINCode = this->passcode_;

  if (chip::QRCodeSetupPayloadGenerator(payload).payloadBase38Representation(
          this->qr_code_) != CHIP_NO_ERROR) {
    this->qr_code_.clear();
    ESP_LOGE(TAG, "  Failed to generate QR code");
  }

  if (chip::ManualSetupPayloadGenerator(payload)
          .payloadDecimalStringRepresentation(this->manual_pairing_code_) !=
      CHIP_NO_ERROR) {
    this->manual_pairing_code_.clear();
    ESP_LOGE(TAG, "  Failed to generate manual pairing code");
  }
}

void MatterComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "Matter:");
  if (this->is_failed()) {
    ESP_LOGE(TAG, "  Failed to initialize!");
    return;
  }

  if (!this->qr_code_.empty()) {
    ESP_LOGCONFIG(TAG, "  SetupQRCode: %s", this->qr_code_.c_str());
    ESP_LOGCONFIG(
        TAG,
        "  QR URL: "
        "https://project-chip.github.io/connectedhomeip/qrcode.html?data=%s",
        this->qr_code_.c_str());
  }
  if (!this->manual_pairing_code_.empty()) {
    ESP_LOGCONFIG(
        TAG, "  Manual pairing code: %s",
        format_manual_pairing_code(this->manual_pairing_code_).c_str());
  }

  chip::DeviceLayer::PlatformMgr().LockChipStack();
  auto &server = chip::Server::GetInstance();
  ESP_LOGCONFIG(
      TAG, "  Commissioning window: %s",
      server.GetCommissioningWindowManager().IsCommissioningWindowOpen()
          ? "open"
          : "closed");
  const auto &fabric_table = server.GetFabricTable();
  if (fabric_table.FabricCount() == 0) {
    ESP_LOGCONFIG(TAG, "  Fabrics: none");
  } else {
    ESP_LOGCONFIG(TAG, "  Fabrics:");
    for (const auto &fabric : fabric_table) {
      char label[chip::kFabricLabelMaxLengthInBytes + 1] = {0};
      auto label_span = fabric.GetFabricLabel();
      memcpy(label, label_span.data(),
             std::min(label_span.size(), sizeof(label) - 1));
      uint64_t compressed_fabric_id = fabric.GetCompressedFabricId();
      uint64_t node_id = fabric.GetNodeId();
      ESP_LOGCONFIG(
          TAG,
          "    [%u] CompressedFabricId: 0x%08" PRIx32 "%08" PRIx32
          ", NodeId: 0x%08" PRIx32 "%08" PRIx32 " (%" PRIu64 ")"
          ", VendorId: 0x%04x%s%s",
          fabric.GetFabricIndex(), (uint32_t)(compressed_fabric_id >> 32),
          (uint32_t)(compressed_fabric_id), (uint32_t)(node_id >> 32),
          (uint32_t)(node_id), node_id, (uint16_t)fabric.GetVendorId(),
          label[0] ? ", Label: " : "", label);
    }
  }
  chip::DeviceLayer::PlatformMgr().UnlockChipStack();
}

} // namespace esphome::matter

#endif // USE_MATTER
