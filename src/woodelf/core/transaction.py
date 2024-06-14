from typing import List


def transaction(func):
    def wrapper(self: Transaction, *args, **kwargs):
        self.enqueue_command(func, *args, **kwargs)
    return wrapper


class Transaction:
    class Command:
        func: callable
        args: list
        kwargs: dict

    cmdq: List[Command]

    def __init__(self):
        self.cmdq = []

    def enqueue_command(self, func: callable, *args, **kwargs):
        cmd = Transaction.Command()
        cmd.func = func
        cmd.args = args
        cmd.kwargs = kwargs

        self.cmdq.append(cmd)

    def on_pre_commit(self):
        pass

    def on_post_commit(self):
        pass

    def commit(self):
        self.on_pre_commit()

        for cmd in self.cmdq:
            cmd.func(self, *cmd.args, **cmd.kwargs)

        self.on_post_commit()
