import json
from .exceptions import IPRPCException


class IPRPCCall:
    attributes = {}

    def __init__(self, **kwargs):
        self.message_type = self.__class__.__name__
        for attr in self.attributes.keys():
            if attr not in kwargs.keys():
                raise IPRPCException(f"Message not valid: {kwargs}. Missing arg {attr}")
        for arg, value in kwargs.items():
            if arg == "message_type":
                pass
            else:
                if arg in self.attributes.keys():
                    intended_type = self.attributes.get(arg)
                    if not type(value) == intended_type:
                        raise IPRPCException(
                            f"Message not valid: {kwargs}. Value {value} is not type {intended_type}."
                        )
                else:
                    raise IPRPCException(
                        f"Message not valid: {kwargs}. Arg {arg} is not valid for this message type."
                    )
            setattr(self, arg, value)

    def serialize_to_json(self):
        return_dict = {"message_type": self.message_type}
        for attr, value in self.attributes.items():
            return_dict.update({attr: getattr(self, attr)})
        return json.dumps(return_dict)


class IPRPCRegistry:
    message_types = {}

    @classmethod
    def register_rpc_call(cls, rpc_class: IPRPCCall):
        cls.message_types.update({rpc_class.__name__: rpc_class})
        return rpc_class

    @classmethod
    def deserialize_from_json(cls, serialized_call: str):
        rpc_dict = json.loads(serialized_call)
        class_name = rpc_dict.get('message_type')
        target_class = cls.message_types.get(class_name)
        return target_class(**rpc_dict)
