from pydantic import BaseModel, IPvAnyAddress, conint
from typing import List, Union, Optional

class BaseClass(BaseModel):
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress

# Pydantic models for validation
class Class0(BaseClass):
    rpi: int  # Assuming rpi is a valid integer

    model_config = {
        "extra": "forbid"  # Forbid extra fields
    }

class Class1(BaseClass):
    rpi: int  # Assuming rpi is a valid integer

    model_config = {
        "extra": "forbid"
    }

class Class3(BaseClass):
    sport: conint(ge=0, le=65535)
    dport: conint(ge=0, le=65535)
    min_random: int # min time in millisecond
    max_random: int # max time in millisecond

    model_config = {
        "extra": "forbid"
    }

class MainModel(BaseModel):
    class0: Optional[Union[Class0, List[Class0]]] = None
    class1: Optional[Union[Class1, List[Class1]]] = None
    class3: Optional[Union[Class3, List[Class3]]] = None

    model_config = {
        "extra": "forbid"  # Forbid extra keys at the top level
    }
