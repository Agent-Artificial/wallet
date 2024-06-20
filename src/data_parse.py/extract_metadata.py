import inspect
from inspect import Signature
from loguru import logger


def extract_function_metadata(func):
    logger.info(f"Extracting metadata from function: {func.__name__}")
    """
    Extracts metadata from a given function.

    Args:
        func (callable): The function to extract metadata from.

    Returns:
        dict: A dictionary containing the following keys:
            - 'function' (str): The name of the function.
            - 'description' (str): The first line of the function's docstring.
            - 'arguments' (list): A list of dictionaries, each representing an argument of the function.
                Each dictionary contains the following keys:
                    - 'name' (str): The name of the argument.
                    - 'type' (type): The type annotation of the argument.
                    - 'optional' (bool): Whether the argument is optional or not.
                    - 'description' (str): The description of the argument, if available in the docstring.
    """
    doc = inspect.getdoc(func) or "No description available"
    description = doc.splitlines()[0]
    signature = inspect.signature(func)
    arguments = [
        {
            "name": name,
            "type": param.annotation,
            "optional": param.default != inspect.Parameter.empty,
            "description": next(
                (
                    line.split(":")[1].strip()
                    for line in doc.splitlines()
                    if line.startswith(f"{name}:")
                ),
                "",
            ),
        }
        for name, param in signature.parameters.items()
    ]
    return {
        "function": func.__name__,
        "description": description,
        "arguments": arguments,
    }
