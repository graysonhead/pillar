import json
from pillar.exceptions import IPRPCMessageException


class IPRPCMessage:
    """
    This class represents an IPRPC
    (InterPlanetary Remote Procedure Call) call. It will be wrapped in a
    message before sending to an IPFS Pubsub queue.
    """
    attributes = {}

    def __init__(self, **kwargs):
        self.message_type = self.__class__.__name__
        for attr in self.attributes.keys():
            if attr not in kwargs.keys():
                raise IPRPCMessageException(f"Message not valid:"
                                            f" {kwargs}. Missing arg {attr}")
        for arg, value in kwargs.items():
            if arg == "message_type":
                pass
            else:
                if arg in self.attributes.keys():
                    intended_type = self.attributes.get(arg)
                    if not type(value) == intended_type:
                        raise IPRPCMessageException(
                            f"Message not valid:"
                            f" {kwargs}. "
                            f"Value {value} is not type {intended_type}."
                        )
                else:
                    raise IPRPCMessageException(
                        f"Message not valid:"
                        f" {kwargs}. "
                        f"Arg {arg} is not valid for this message type."
                    )
            setattr(self, arg, value)

    def serialize_to_json(self):
        return json.dumps(self.serialize_to_dict())

    def serialize_to_dict(self):
        return_dict = {"message_type": self.message_type}
        for attr, value in self.attributes.items():
            return_dict.update({attr: getattr(self, attr)})
        return return_dict

    def __repr__(self):
        return_string = f"<{self.__class__.__name__}"
        if self.attributes.__len__() >= 1:
            last_attr = list(self.attributes.keys())[-1]
            return_string = return_string + ": "
            for attr in self.attributes.keys():
                return_string = return_string + f"{attr}={getattr(self, attr)}"
                if attr == last_attr:
                    return_string = return_string + ">"
                else:
                    return_string = return_string + ", "
        else:
            return_string = return_string + ">"
        return return_string


class IPRPCRegistry:
    message_types = {}

    @classmethod
    def register_rpc_call(cls, rpc_class: IPRPCMessage):
        cls.message_types.update({rpc_class.__name__: rpc_class})
        return rpc_class

    @classmethod
    def deserialize_from_json(cls, serialized_call: str):
        rpc_dict = json.loads(serialized_call)
        return IPRPCRegistry.deserialize_from_dict(rpc_dict)

    @classmethod
    def deserialize_from_dict(cls, serialized_call: dict):
        class_name = serialized_call.get('message_type')
        target_class = cls.message_types.get(class_name)
        try:
            return target_class(**serialized_call)
        except TypeError:
            raise IPRPCMessageException(f"Invalid RPC Call {class_name}")


@IPRPCRegistry.register_rpc_call
class PingRequestCall(IPRPCMessage):
    attributes = {}


@IPRPCRegistry.register_rpc_call
class PingReplyCall(IPRPCMessage):
    attributes = {}


@IPRPCRegistry.register_rpc_call
class PeeringHello(IPRPCMessage):
    attributes = {"initiator_id": str}


@IPRPCRegistry.register_rpc_call
class PeeringHelloResponse(IPRPCMessage):
    attributes = {"responder_id": str}
