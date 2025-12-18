import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.recipes import (
    build_recipe_execution,
    resolve_recipe_plan,
    validate_recipe_name,
)


class RecipeValidationTests(unittest.TestCase):
    def test_validate_recipe_name_accepts(self) -> None:
        for name in ["base", "web-01", "a_b.c", "Z9"]:
            validate_recipe_name(name)

    def test_validate_recipe_name_rejects(self) -> None:
        invalid = ["", "bad name", "@foo", "a" * 65]
        for name in invalid:
            with self.assertRaises(ValueError):
                validate_recipe_name(name)


class RecipeResolutionTests(unittest.TestCase):
    def test_resolve_recipe_plan_orders_dependencies(self) -> None:
        recipes = {
            "base": {"dependencies": []},
            "db": {"dependencies": ["base"]},
            "app": {"dependencies": ["base", "db"]},
        }
        plan = resolve_recipe_plan("app", recipes, include_dependencies=True)
        self.assertEqual(plan, ["base", "db", "app"])

    def test_resolve_recipe_plan_detects_cycle(self) -> None:
        recipes = {
            "alpha": {"dependencies": ["beta"]},
            "beta": {"dependencies": ["alpha"]},
        }
        with self.assertRaises(ValueError):
            resolve_recipe_plan("alpha", recipes, include_dependencies=True)

    def test_resolve_recipe_plan_missing_dependency(self) -> None:
        recipes = {"alpha": {"dependencies": ["missing"]}}
        with self.assertRaises(ValueError):
            resolve_recipe_plan("alpha", recipes, include_dependencies=True)


class RecipeExecutionTests(unittest.TestCase):
    def test_build_recipe_execution_renders_and_orders(self) -> None:
        recipes = {
            "base": {
                "dependencies": [],
                "packages": ["{{lang}}3", "pip"],
                "commands": ["echo {{lang}}"],
                "parameters": {"lang": "python"},
                "required_parameters": [],
            },
            "app": {
                "dependencies": ["base"],
                "packages": [],
                "commands": ["useradd -m {{user}}"],
                "parameters": {"user": "deploy"},
                "required_parameters": ["user"],
            },
        }
        plan, steps = build_recipe_execution("app", recipes, include_dependencies=True, overrides={"user": "alice"})
        self.assertEqual(plan, ["base", "app"])
        self.assertEqual(steps[0]["packages"], ["python3", "pip"])
        self.assertEqual(steps[0]["commands"], ["echo python"])
        self.assertEqual(steps[1]["commands"], ["useradd -m alice"])

    def test_build_recipe_execution_requires_parameters(self) -> None:
        recipes = {
            "app": {
                "dependencies": [],
                "packages": [],
                "commands": ["echo {{user}}"],
                "parameters": {},
                "required_parameters": ["user"],
            }
        }
        with self.assertRaises(ValueError):
            build_recipe_execution("app", recipes, include_dependencies=True, overrides={})

    def test_build_recipe_execution_missing_template_param(self) -> None:
        recipes = {
            "app": {
                "dependencies": [],
                "packages": [],
                "commands": ["echo {{missing}}"],
                "parameters": {},
                "required_parameters": [],
            }
        }
        with self.assertRaises(ValueError):
            build_recipe_execution("app", recipes, include_dependencies=True, overrides={})


if __name__ == "__main__":
    unittest.main()
