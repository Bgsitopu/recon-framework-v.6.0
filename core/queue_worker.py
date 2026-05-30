"""Async queue-based worker pool for concurrent tasks."""
import asyncio
from typing import Callable, Iterable, Any
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn


async def run_workers(
    tasks: Iterable[Any],
    worker_fn: Callable,
    concurrency: int = 50,
    description: str = "Working",
    *args, **kwargs
) -> list:
    """
    Run worker_fn(item, *args, **kwargs) for each item in tasks concurrently.
    Returns list of non-None results.
    """
    queue: asyncio.Queue = asyncio.Queue()
    for item in tasks:
        await queue.put(item)

    results = []
    lock = asyncio.Lock()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
    ) as progress:
        task_id = progress.add_task(description, total=queue.qsize())

        async def _worker():
            while True:
                try:
                    item = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                try:
                    result = await worker_fn(item, *args, **kwargs)
                    if result is not None:
                        async with lock:
                            if isinstance(result, list):
                                results.extend(result)
                            else:
                                results.append(result)
                except Exception:
                    pass
                finally:
                    progress.advance(task_id)
                    queue.task_done()

        workers = [asyncio.create_task(_worker()) for _ in range(min(concurrency, queue.qsize() or 1))]
        await asyncio.gather(*workers)

    return results
