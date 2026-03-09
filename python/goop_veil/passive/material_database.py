"""Material database — properties of building materials for WiFi attenuation.

Provides cost, availability, and attenuation data for materials that can
degrade WiFi CSI quality and protect against sensing through walls.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class MaterialInfo(BaseModel):
    """Properties of a building material for WiFi attenuation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    display_name: str
    #: Attenuation coefficient identifier for Rust core
    material_key: str
    #: Typical thickness for residential use (meters)
    typical_thickness_m: float
    #: Approximate cost per square meter (USD)
    cost_per_m2_usd: float
    #: Installation difficulty (1=easy DIY, 5=professional required)
    install_difficulty: int = Field(ge=1, le=5)
    #: Whether the material is commonly available at hardware stores
    readily_available: bool = True
    #: Aesthetic impact (1=invisible, 5=major visual change)
    aesthetic_impact: int = Field(ge=1, le=5)
    #: Description of the material and its use
    description: str = ""


# =============================================================================
# Material catalog
# =============================================================================

MATERIALS: dict[str, MaterialInfo] = {
    "aluminum_foil": MaterialInfo(
        name="aluminum_foil",
        display_name="Aluminum Foil (behind drywall)",
        material_key="metal_foil",
        typical_thickness_m=0.00002,  # 20 microns
        cost_per_m2_usd=0.50,
        install_difficulty=2,
        readily_available=True,
        aesthetic_impact=1,
        description="Thin aluminum foil behind drywall or wallpaper. "
        "Extremely effective RF attenuator at minimal cost.",
    ),
    "rf_paint": MaterialInfo(
        name="rf_paint",
        display_name="RF Shielding Paint",
        material_key="rf_absorber",
        typical_thickness_m=0.0005,  # 0.5mm when dried
        cost_per_m2_usd=15.00,
        install_difficulty=2,
        readily_available=False,
        aesthetic_impact=1,
        description="Carbon/nickel-based paint applied under normal paint. "
        "Provides 20-40 dB attenuation at 2.4 GHz.",
    ),
    "rf_window_film": MaterialInfo(
        name="rf_window_film",
        display_name="RF Shielding Window Film",
        material_key="metal_foil",
        typical_thickness_m=0.0001,  # 0.1mm
        cost_per_m2_usd=25.00,
        install_difficulty=2,
        readily_available=False,
        aesthetic_impact=2,
        description="Metallic window film that blocks RF while allowing visible light. "
        "Transparent with slight tint.",
    ),
    "concrete_wall": MaterialInfo(
        name="concrete_wall",
        display_name="Concrete Wall",
        material_key="concrete",
        typical_thickness_m=0.15,
        cost_per_m2_usd=80.00,
        install_difficulty=5,
        readily_available=True,
        aesthetic_impact=5,
        description="Existing or new concrete wall. Provides natural high attenuation.",
    ),
    "brick_wall": MaterialInfo(
        name="brick_wall",
        display_name="Brick Wall",
        material_key="brick",
        typical_thickness_m=0.10,
        cost_per_m2_usd=60.00,
        install_difficulty=5,
        readily_available=True,
        aesthetic_impact=4,
        description="Brick provides moderate WiFi attenuation.",
    ),
    "metal_mesh": MaterialInfo(
        name="metal_mesh",
        display_name="Metal Mesh Screen",
        material_key="metal",
        typical_thickness_m=0.001,
        cost_per_m2_usd=8.00,
        install_difficulty=3,
        readily_available=True,
        aesthetic_impact=3,
        description="Fine metal mesh (window screen grade) behind walls or in ceilings. "
        "Acts as Faraday cage element.",
    ),
    "drywall_extra": MaterialInfo(
        name="drywall_extra",
        display_name="Additional Drywall Layer",
        material_key="drywall",
        typical_thickness_m=0.013,
        cost_per_m2_usd=5.00,
        install_difficulty=3,
        readily_available=True,
        aesthetic_impact=2,
        description="Extra layer of drywall. Minimal attenuation alone but good base layer.",
    ),
    "fiberglass_insulation": MaterialInfo(
        name="fiberglass_insulation",
        display_name="Fiberglass Insulation",
        material_key="fiberglass",
        typical_thickness_m=0.09,  # R-13 ~3.5 inches
        cost_per_m2_usd=4.00,
        install_difficulty=3,
        readily_available=True,
        aesthetic_impact=1,
        description="Standard fiberglass insulation in wall cavities. "
        "Minimal WiFi attenuation alone.",
    ),
    "water_wall": MaterialInfo(
        name="water_wall",
        display_name="Decorative Water Wall/Feature",
        material_key="water",
        typical_thickness_m=0.05,
        cost_per_m2_usd=100.00,
        install_difficulty=4,
        readily_available=True,
        aesthetic_impact=3,
        description="Indoor water feature (fountain, water wall). "
        "Water's high dielectric constant provides good attenuation.",
    ),
}


def get_material(name: str) -> MaterialInfo | None:
    """Look up a material by name."""
    return MATERIALS.get(name)


def get_all_materials() -> list[MaterialInfo]:
    """Get all materials sorted by cost-effectiveness."""
    return sorted(MATERIALS.values(), key=lambda m: m.cost_per_m2_usd)


def get_materials_under_budget(
    area_m2: float,
    budget_usd: float,
) -> list[MaterialInfo]:
    """Get materials that fit within budget for a given area."""
    return [
        m
        for m in get_all_materials()
        if m.cost_per_m2_usd * area_m2 <= budget_usd
    ]
