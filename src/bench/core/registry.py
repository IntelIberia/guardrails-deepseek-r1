"""Registro explícito de fábricas, sin importaciones dinámicas desde YAML."""

from typing import Generic, TypeVar

Factory = TypeVar("Factory")


class RegistryError(ValueError):
    """Un adaptador no existe o se ha intentado registrar dos veces."""


class AdapterRegistry(Generic[Factory]):
    """Asocia nombres de configuración con fábricas tipadas por el llamador."""

    def __init__(self) -> None:
        self._factories: dict[str, Factory] = {}

    def register(self, name: str, factory: Factory) -> None:
        """Registra una fábrica y rechaza sustituciones accidentales."""
        if not isinstance(name, str) or not name.strip() or name != name.strip():
            raise RegistryError("El adaptador debe tener un nombre no vacío")
        if name in self._factories:
            raise RegistryError(f"Adaptador ya registrado: {name}")
        self._factories[name] = factory

    def resolve(self, name: str) -> Factory:
        """Devuelve la fábrica declarada o informa de los nombres disponibles."""
        try:
            return self._factories[name]
        except KeyError as exc:
            available = ", ".join(self.names()) or "(ninguno)"
            raise RegistryError(f"Adaptador desconocido: {name}; disponibles: {available}") from exc

    def names(self) -> tuple[str, ...]:
        """Lista los nombres de manera estable para planes y diagnósticos."""
        return tuple(sorted(self._factories))
