import asyncio


async def handler_loop(handler,
                       sleep=0,
                       run_once: bool = False) -> None:
    """
    Used to implement looping logic to non-looping handlers.

    This method mostly exists to make unit testing easier.
    :param handler:
        The async method to run
    :param sleep:
        Time to asyncio.sleep between each loop.
    :param run_once:
        Run once then break the loop.
    """
    while True:
        await handler()
        if run_once:
            break
        await asyncio.sleep(sleep)
