from typing import Any, Dict, TypeVar

KeyType = TypeVar("KeyType")


def deep_update(
    mapping: Dict[KeyType, Any], *updating_mappings: Dict[KeyType, Any], merge_lists: bool = False
) -> Dict[KeyType, Any]:
    """
    Recursively update a dictionary.
    """
    updated_mapping = mapping.copy()
    for updating_mapping in updating_mappings:
        for k, v in updating_mapping.items():
            if k in updated_mapping and isinstance(updated_mapping[k], dict) and isinstance(v, dict):
                updated_mapping[k] = deep_update(updated_mapping[k], v, merge_lists=merge_lists)
            elif merge_lists and k in updated_mapping and isinstance(updated_mapping[k], list) and isinstance(v, list):
                updated_mapping[k] = updated_mapping[k] + v
            else:
                updated_mapping[k] = v
    return updated_mapping
