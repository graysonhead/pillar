import json
from .exceptions import IPRPCException


class IPRPCCall:
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
                raise IPRPCException(f"Message not valid:"
                                     f" {kwargs}. Missing arg {attr}")
        for arg, value in kwargs.items():
            if arg == "message_type":
                pass
            else:
                if arg in self.attributes.keys():
                    intended_type = self.attributes.get(arg)
                    if not type(value) == intended_type:
                        raise IPRPCException(
                            f"Message not valid:"
                            f" {kwargs}. "
                            f"Value {value} is not type {intended_type}."
                        )
                else:
                    raise IPRPCException(
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


class IPRPCRegistry:
    message_types = {}

    @classmethod
    def register_rpc_call(cls, rpc_class: IPRPCCall):
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
        return target_class(**serialized_call)


class IPRPCMessageType:
    INLINE = 1
    INLINE_ENCRYPTED = 2
    CID = 3
    CID_ENCRYPTED = 4


class IPRPCMessage:

    def __init__(self,
                 msg_type: IPRPCMessageType,
                 dst_peer: str = '',
                 broadcast: bool = False,
                 msg_cid: str = '',
                 call: IPRPCCall = None
                 ):

        self.msg_type = msg_type
        if dst_peer:
            self.dst_peer = dst_peer
        else:
            self.dst_peer = None
        if msg_cid:
            self.msg_cid = msg_cid
        else:
            self.msg_cid = None
        self.broadcast = broadcast
        if call:
            self.call = call
        else:
            self.call = None
        self._validate()

    def _validate(self):
        if self.broadcast and self.dst_peer:
            raise IPRPCException("Invalid message, "
                                 "cannot have broadcast arg "
                                 "set with dst_peer arg present")
        if not self.broadcast and not self.dst_peer:
            raise IPRPCException("Invalid message, broadcast False but missing"
                                 " dst_peer arg")
        if self.msg_type == IPRPCMessageType.INLINE \
                or self.msg_type == IPRPCMessageType.INLINE_ENCRYPTED:
            if self.msg_cid:
                raise IPRPCException("Invalid message, "
                                     "cannot be type inline with msg_cid arg")
            if not self.call:
                raise IPRPCException("Invalid message, "
                                     "INLINE type must have call arg")
        if self.msg_type == IPRPCMessageType.CID \
                or self.msg_type == IPRPCMessageType.CID_ENCRYPTED:
            if self.call:
                raise IPRPCException("Invalid message, "
                                     "cannot be type CID with call arg")
            if not self.msg_cid:
                raise IPRPCException("Invalid message, "
                                     "CID type must have msg_cid arg")

    def serialize_to_json(self):
        if self.msg_type == IPRPCMessageType.INLINE:
            return self._dumps_inline_unencrypted()

    def _dumps_inline_unencrypted(self):
        result_dict = {'msg_type': self.msg_type,
                       'broadcast': self.broadcast,
                       'call': self.call.serialize_to_dict()}
        if self.msg_cid:
            result_dict.update({"msg_cid": self.msg_cid})
        if self.broadcast:
            result_dict.update({"broadcast": True})
        else:
            result_dict.update({"dst_peer": self.dst_peer})
        return json.dumps(result_dict)

    @staticmethod
    def deserialize_from_json(json_string: str):
        pass
        message_dict = json.loads(json_string)
        if message_dict.get("call", None):
            call_instance = \
                IPRPCRegistry.deserialize_from_dict(message_dict.get('call'))
            message_dict.update({'call': call_instance})
        return IPRPCMessage(**message_dict)


class PingType:
    REQUEST = 1
    RESPONSE = 2


@IPRPCRegistry.register_rpc_call
class PingRPC(IPRPCCall):
    attributes = {"ping_type": int}
