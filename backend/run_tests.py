import os
import sys

import pytest

if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))
    raise SystemExit(pytest.main(["-q", "tests/test_paypal.py"]))
