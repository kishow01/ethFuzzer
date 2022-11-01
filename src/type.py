from typing import Union, Tuple, Dict, List, Set, Optional, Callable, Any

Option = Dict[str, Any]
Expansion = Union[str, Tuple[str, Option]]
Grammar = Dict[str, List[Expansion]]
DerivationTree = Tuple[str, Optional[List[Any]]]