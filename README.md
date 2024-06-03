# EuroMeasure-py
This repository contains python library for communicating with, and controlling, EuroMeasure system.

## Installation
To install this library run:
```bash
pip install git+https://github.com/JJendryka/EuroMeasure-py.git
```

## Examples
### Read voltage
```python
from euromeasure import EuroMeasure
em = EuroMeasure() # Create EuroMeasure object
em.connect("/dev/ttyACM0") # Connect to the system on port /dev/ttyACM0
print(em.get_voltmeter_voltage(2)) # Get and print voltage from second channel of the voltmeter.
```