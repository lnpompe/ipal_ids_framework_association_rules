
def convert_valve(vars):
    if vars[0] == None:
        return None
    return round(vars[0] / 65535.0 * 100, 4)

def convert_flow(vars):
    if vars[0] == None:
        return None
    return round(vars[0] / 65535.0 * 500, 2)

def convert_pressure(vars):
    if vars[0] == None:
        return None
    return round(vars[0] / 65535.0 * 3200)

JS = {
    "protocols": ["modbus"],
    "rename": { 
        "192.168.95.10:502:247": "Feed1",
        "192.168.95.11:502:247": "Feed2",
        "192.168.95.12:502:247": "Purge",
        "192.168.95.13:502:247": "Product",
        "192.168.95.14:502:247": "Tank",
        "192.168.95.15:502:247": "Analyzer",
        "192.168.95.2:502:1": "PLC",
    },
    "rules": [
        # Feed 1 
        {   # valve
            "dest": "Feed1",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_valve,
            "name": "valve.position",
            "remove": True,
        },
        {
            "src": "Feed1",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_valve,
            "name": "valve.position",
            "remove": True,
        },
        {   # flow
            "dest": "Feed1",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_flow,
            "name": "flow",
            "remove": True,
        },
        {   
            "src": "Feed1",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_flow,
            "name": "flow",
            "remove": True,
        },
        # Feed 2
        {   # valve
            "dest": "Feed2",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_valve,
            "name": "valve.position",
            "remove": True,
        },
        {   
            "src": "Feed2",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_valve,
            "name": "valve.position",
            "remove": True,
        },
        {   # flow
            "dest": "Feed2",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_flow,
            "name": "flow",
            "remove": True,
        },
        {   
            "src": "Feed2",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_flow,
            "name": "flow",
            "remove": True,
        },
        # Purge
        {   # valve
            "dest": "Purge",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_valve,
            "name": "valve.position",
            "remove": True,
        },
        {   
            "src": "Purge",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_valve,
            "name": "valve.position",
            "remove": True,
        },
        {   # flow
            "dest": "Purge",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_flow,
            "name": "flow",
            "remove": True,
        },
        {   
            "src": "Purge",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_flow,
            "name": "flow",
            "remove": True,
        },
        # Product
        {   # valve
            "dest": "Product",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_valve,
            "name": "valve.position",
            "remove": True,
        },
        {
            "src": "Product",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_valve,
            "name": "valve.position",
            "remove": True,
        },
        {   # flow
            "dest": "Product",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_flow,
            "name": "flow",
            "remove": True,
        },
        {   
            "src": "Product",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_flow,
            "name": "flow",
            "remove": True,
        },
        # Tank
        {   # pressure
            "dest": "Tank",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_pressure,
            "name": "pressure",
            "remove": True,
        },
        {   
            "src": "Tank",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_pressure,
            "name": "pressure",
            "remove": True,
        },
        {   # level
            "dest": "Tank",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_valve,
            "name": "level",
            "remove": True,
        },
        {   
            "src": "Tank",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_valve,
            "name": "level",
            "remove": True,
        },
        # Analyzer
        {   # A in purge
            "dest": "Analyzer",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_valve,
            "name": "A.in.purge",
            "remove": True,
        },
        {   
            "src": "Analyzer",
            "type": "4",
            "var": ["input.register.1"],
            "method": convert_valve,
            "name": "A.in.purge",
            "remove": True,
        },
        {   # B in purge
            "dest": "Analyzer",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_valve,
            "name": "B.in.purge",
            "remove": True,
        },
        {   
            "src": "Analyzer",
            "type": "4",
            "var": ["input.register.2"],
            "method": convert_valve,
            "name": "B.in.purge",
            "remove": True,
        },
        {   # C in purge
            "dest": "Analyzer",
            "type": "4",
            "var": ["input.register.3"],
            "method": convert_valve,
            "name": "C.in.purge",
            "remove": True,
        },
        {   
            "src": "Analyzer",
            "type": "4",
            "var": ["input.register.3"],
            "method": convert_valve,
            "name": "C.in.purge",
            "remove": True,
        },
        # Remove
        {
            "var": [
                "input.register.0",
                "holding.register.1",
                "coil.40",
                "coil.0",
                "coil.1",
                "coil.2",
                "coil.3",
                "coil.4",
                "coil.5",
                "coil.6",
                "coil.7",
            ],
            "remove": True,
        },
        # Remove PLC-to-HMI data 
        {
            "src": "PLC",
            "var": [
                "input.register.0",
                "input.register.1",
                "input.register.2",
                "input.register.3",
                "input.register.4",
                "input.register.5",
                "input.register.6",
                "input.register.7",
                "input.register.8",
                "input.register.9",
                "input.register.10",
                "input.register.11",
                "input.register.12",
            ],
            "remove": True,
        }
    ]
}
