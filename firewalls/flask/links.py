from typing import Callable, ParamSpec, TypeVar

from flask_smorest import Blueprint

P = ParamSpec("P")
T = TypeVar("T")


def operation(
    blueprint: Blueprint, operation_id: str
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        return blueprint.doc(**{"operationId": operation_id})(func)

    return decorator


def links(
    blueprint: Blueprint,
    status: int,
    name: str,
    operation_id: str,
    parameters: dict[str, tuple[str, ...]],
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        return blueprint.doc(
            **{
                "responses": {
                    status: {
                        "links": {
                            name: {
                                "operationId": operation_id,
                                "parameters": {
                                    name_: f"$response.body#/{'/'.join(path)}"
                                    for name_, path in parameters.items()
                                },
                            }
                        }
                    }
                }
            }
        )(func)

    return decorator
