"""CLI configuration for PAC IPv6 address profiles."""

import click

import utilities_common.cli as clicommon
from .validated_config_db_connector import ValidatedConfigDBConnector


PROFILE_TABLE = "PAC_IPV6_PROFILE"
PROPERTY_TABLE = "PAC_IPV6_PROFILE_PROPERTY"
PORT_PROFILE_TABLE = "PAC_PORT_IPV6_PROFILE"
PROPERTY_TYPES = ("literal", "tenant-id", "port-id")


def _config_db(db):
    connector = ValidatedConfigDBConnector(db.cfgdb)
    connector.connect()
    return connector


def _parse_uint(value, name, maximum=(1 << 64) - 1):
    try:
        parsed = int(value, 0)
    except (TypeError, ValueError):
        raise click.ClickException("{} must be an unsigned integer".format(name))
    if parsed < 0 or parsed > maximum:
        raise click.ClickException("{} must be between 0 and {}".format(name, maximum))
    return parsed


def _profile_properties(config_db, profile):
    return {
        key[1]: fields
        for key, fields in config_db.get_table(PROPERTY_TABLE).items()
        if isinstance(key, tuple) and len(key) == 2 and key[0] == profile
    }


def _validate_property(config_db, profile, property_name, property_type,
                       offset, length, value, ignore_existing=False):
    ctx = click.get_current_context()
    if profile not in config_db.get_table(PROFILE_TABLE):
        ctx.fail("IPv6 profile '{}' does not exist".format(profile))
    if property_type not in PROPERTY_TYPES:
        ctx.fail("type must be one of: {}".format(", ".join(PROPERTY_TYPES)))
    if offset < 0 or offset > 127 or length < 1 or length > 64 or offset + length > 128:
        ctx.fail("property bit range must fit in the 128-bit IPv6 address")

    if property_type == "literal":
        if value is None:
            ctx.fail("--value is required for a literal property")
        if length > 32:
            ctx.fail("literal properties can be at most 32 bits long")
        literal = _parse_uint(value, "value", min((1 << length) - 1, (1 << 32) - 1))
    elif property_type == "tenant-id":
        if length > 32:
            ctx.fail("tenant-id properties can be at most 32 bits long")
        if value is not None:
            ctx.fail("--value is only valid for a literal property")
        literal = None
    elif value is not None:
        ctx.fail("--value is only valid for a literal property")
    else:
        literal = None

    start, end = offset, offset + length
    for existing_name, fields in _profile_properties(config_db, profile).items():
        if ignore_existing and existing_name == property_name:
            continue
        other_start = int(fields["offset"])
        other_end = other_start + int(fields["length"])
        if start < other_end and other_start < end:
            ctx.fail("property bit range overlaps '{}'".format(existing_name))
    return literal


@click.group(cls=clicommon.AbbreviationGroup)
def pac():
    """Port Access Control configuration tasks"""
    pass


@pac.group(name="ipv6-profile", cls=clicommon.AbbreviationGroup)
def ipv6_profile():
    """Configure PAC dynamic IPv6 profiles"""
    pass


@ipv6_profile.command("add")
@click.argument("profile", metavar="<profile>")
@click.option("--route-summary-prefix-length", type=click.IntRange(1, 128),
              help="Advertise this aggregate prefix while a matching PAC session is active")
@clicommon.pass_db
def add_profile(db, profile, route_summary_prefix_length):
    """Create a PAC IPv6 address profile"""
    config_db = _config_db(db)
    ctx = click.get_current_context()
    if profile in config_db.get_table(PROFILE_TABLE):
        ctx.fail("IPv6 profile '{}' already exists".format(profile))
    fields = {}
    if route_summary_prefix_length is not None:
        fields["route_summary_prefix_length"] = str(route_summary_prefix_length)
    try:
        config_db.set_entry(PROFILE_TABLE, profile, fields)
    except ValueError as error:
        ctx.fail("Invalid ConfigDB: {}".format(error))
    click.echo("IPv6 profile {} added".format(profile))


@ipv6_profile.command("set")
@click.argument("profile", metavar="<profile>")
@click.option("--route-summary-prefix-length", type=click.IntRange(1, 128),
              help="Advertise this aggregate prefix while a matching PAC session is active")
@click.option("--no-route-summary", is_flag=True,
              help="Disable route summary advertisement for this profile")
@clicommon.pass_db
def set_profile(db, profile, route_summary_prefix_length, no_route_summary):
    """Update route-summary settings for a PAC IPv6 profile"""
    config_db = _config_db(db)
    ctx = click.get_current_context()
    if profile not in config_db.get_table(PROFILE_TABLE):
        ctx.fail("IPv6 profile '{}' does not exist".format(profile))
    if route_summary_prefix_length is None and not no_route_summary:
        ctx.fail("Specify --route-summary-prefix-length or --no-route-summary")
    if route_summary_prefix_length is not None and no_route_summary:
        ctx.fail("--route-summary-prefix-length and --no-route-summary cannot be combined")
    fields = dict(config_db.get_entry(PROFILE_TABLE, profile) or {})
    if no_route_summary:
        fields.pop("route_summary_prefix_length", None)
    else:
        fields["route_summary_prefix_length"] = str(route_summary_prefix_length)
    try:
        config_db.set_entry(PROFILE_TABLE, profile, fields)
    except ValueError as error:
        ctx.fail("Invalid ConfigDB: {}".format(error))
    click.echo("IPv6 profile {} updated".format(profile))


@ipv6_profile.command("delete")
@click.argument("profile", metavar="<profile>")
@clicommon.pass_db
def delete_profile(db, profile):
    """Delete a PAC IPv6 profile"""
    config_db = _config_db(db)
    ctx = click.get_current_context()
    if profile not in config_db.get_table(PROFILE_TABLE):
        ctx.fail("IPv6 profile '{}' does not exist".format(profile))
    if _profile_properties(config_db, profile):
        ctx.fail("Delete the profile's properties before deleting the profile")
    if any(fields.get("profile") == profile
           for fields in config_db.get_table(PORT_PROFILE_TABLE).values()):
        ctx.fail("Unbind interfaces from the profile before deleting it")
    try:
        config_db.set_entry(PROFILE_TABLE, profile, None)
    except ValueError as error:
        ctx.fail("Invalid ConfigDB: {}".format(error))
    click.echo("IPv6 profile {} deleted".format(profile))


@ipv6_profile.group(name="property", cls=clicommon.AbbreviationGroup)
def property_group():
    """Configure address properties within a PAC IPv6 profile"""
    pass


@property_group.command("add")
@click.argument("profile", metavar="<profile>")
@click.argument("property_name", metavar="<property>")
@click.option("--type", "property_type", required=True, type=click.Choice(PROPERTY_TYPES))
@click.option("--offset", required=True, type=click.IntRange(0, 127))
@click.option("--length", required=True, type=click.IntRange(1, 64))
@click.option("--value", help="Unsigned decimal or 0x-prefixed value for literal properties")
@click.option("--isolation/--no-isolation", default=None,
              help="Include these bits in the tenant isolation match")
@clicommon.pass_db
def add_property(db, profile, property_name, property_type, offset, length, value, isolation):
    """Add a literal, tenant-id, or port-id address property"""
    config_db = _config_db(db)
    ctx = click.get_current_context()
    if property_name in _profile_properties(config_db, profile):
        ctx.fail("Property '{}' already exists in profile '{}'".format(property_name, profile))
    literal = _validate_property(config_db, profile, property_name, property_type,
                                 offset, length, value)
    if isolation is None:
        isolation = property_type == "tenant-id"
    fields = {
        "type": property_type,
        "offset": str(offset),
        "length": str(length),
        "isolation": "true" if isolation else "false",
    }
    if literal is not None:
        fields["value"] = str(literal)
    try:
        config_db.set_entry(PROPERTY_TABLE, (profile, property_name), fields)
    except ValueError as error:
        ctx.fail("Invalid ConfigDB: {}".format(error))
    click.echo("Property {} added to IPv6 profile {}".format(property_name, profile))


@property_group.command("delete")
@click.argument("profile", metavar="<profile>")
@click.argument("property_name", metavar="<property>")
@clicommon.pass_db
def delete_property(db, profile, property_name):
    """Delete an address property from a PAC IPv6 profile"""
    config_db = _config_db(db)
    ctx = click.get_current_context()
    if property_name not in _profile_properties(config_db, profile):
        ctx.fail("Property '{}' does not exist in profile '{}'".format(property_name, profile))
    try:
        config_db.set_entry(PROPERTY_TABLE, (profile, property_name), None)
    except ValueError as error:
        ctx.fail("Invalid ConfigDB: {}".format(error))
    click.echo("Property {} deleted from IPv6 profile {}".format(property_name, profile))


@ipv6_profile.command("bind")
@click.argument("interface", metavar="<interface>")
@click.argument("profile", metavar="<profile>")
@click.option("--port-id", default="auto", show_default=True,
              help="Use 'auto' to derive it from the switch port MAC, or set an integer")
@clicommon.pass_db
def bind_profile(db, interface, profile, port_id):
    """Bind an IPv6 profile to a physical PAC interface"""
    config_db = _config_db(db)
    ctx = click.get_current_context()
    if not clicommon.is_valid_port(db.cfgdb, interface):
        ctx.fail("'{}' is not a physical port".format(interface))
    if profile not in config_db.get_table(PROFILE_TABLE):
        ctx.fail("IPv6 profile '{}' does not exist".format(profile))
    profile_properties = _profile_properties(config_db, profile)
    if not any(fields.get("type") == "tenant-id" for fields in profile_properties.values()):
        ctx.fail("profile '{}' needs a tenant-id property before it can be bound".format(profile))
    port_property = next((fields for fields in profile_properties.values()
                          if fields.get("type") == "port-id"), None)
    if port_id != "auto":
        if port_property is None:
            ctx.fail("profile '{}' has no port-id property".format(profile))
        numeric_port_id = _parse_uint(port_id, "port-id")
        if port_property is not None:
            bit_length = int(port_property["length"])
            if numeric_port_id >= (1 << bit_length):
                ctx.fail("port-id does not fit the profile's {}-bit port-id property".format(bit_length))
        port_id = str(numeric_port_id)
    try:
        config_db.set_entry(PORT_PROFILE_TABLE, interface,
                            {"profile": profile, "port_id": port_id})
    except ValueError as error:
        ctx.fail("Invalid ConfigDB: {}".format(error))
    click.echo("IPv6 profile {} bound to {} (port-id {})".format(profile, interface, port_id))


@ipv6_profile.command("unbind")
@click.argument("interface", metavar="<interface>")
@clicommon.pass_db
def unbind_profile(db, interface):
    """Remove the PAC IPv6 profile binding from an interface"""
    config_db = _config_db(db)
    if interface not in config_db.get_table(PORT_PROFILE_TABLE):
        click.echo("No IPv6 profile is bound to {}".format(interface))
        return
    try:
        config_db.set_entry(PORT_PROFILE_TABLE, interface, None)
    except ValueError as error:
        click.get_current_context().fail("Invalid ConfigDB: {}".format(error))
    click.echo("IPv6 profile unbound from {}".format(interface))


pac.add_command(ipv6_profile)
