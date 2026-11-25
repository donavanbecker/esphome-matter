"""Matter diagnostic binary sensors."""

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import binary_sensor
from esphome.const import (
    CONF_ID,
    DEVICE_CLASS_CONNECTIVITY,
    ENTITY_CATEGORY_DIAGNOSTIC,
)

from .types import MatterComponent

DEPENDENCIES = ["matter"]

CONF_COMMISSIONING_WINDOW = "commissioning_window"

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.use_id(MatterComponent),
        cv.Optional(CONF_COMMISSIONING_WINDOW): binary_sensor.binary_sensor_schema(
            device_class=DEVICE_CLASS_CONNECTIVITY,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon="mdi:lan-connect",
        ),
    }
).extend(cv.COMPONENT_SCHEMA)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_ID])
    if conf := config.get(CONF_COMMISSIONING_WINDOW):
        sens = await binary_sensor.new_binary_sensor(conf)
        cg.add(parent.set_commissioning_window_sensor(sens))
