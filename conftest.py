import os
import sys

# Allow `import alert_rules` from tests/ without installing the project as a package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
