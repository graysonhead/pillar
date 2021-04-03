import asynctest
from ..async_untils import handler_loop
from unittest import skip

@skip
class TestHandlerLoop(asynctest.TestCase):

    async def test_handler_loop(self):
        fake_method = asynctest.CoroutineMock()
        await handler_loop(fake_method, run_once=True)
        fake_method.assert_awaited()
