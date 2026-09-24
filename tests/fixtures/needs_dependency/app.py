"""
Target that imports a third-party package the default sandbox image lacks.

Used to check that a dependency gap is graded ENV_INCOMPLETE through the real
sandbox, not UNPROVEN.
"""

import yaml


def load(text):
    return yaml.load(text, Loader=yaml.Loader)
