#!/usr/bin/env python3
import argparse
import json
import random
import sys
import uuid
from pathlib import Path

try:
    from faker import Faker
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: Faker. Install it with `pip install Faker`."
    ) from exc


ROLE_CHOICES = [
    "Reader",
    "Contributor",
    "Billing Reader",
    "User Access Administrator",
    "Security Administrator",
    "Application Administrator",
    "Privileged Access Administrator",
]

DOMAINS = [
    ("finance", "FIN"),
    ("security", "SEC"),
    ("engineering", "ENG"),
    ("hr", "HR"),
    ("sales", "SAL"),
    ("operations", "OPS"),
    ("platform", "PLT"),
]

ENVIRONMENTS = ["dev", "test", "prod"]
CRITICALITIES = ["low", "medium", "high"]
GROUP_TYPES = ["USR", "ADM", "SEC"]


def build_group(rng: random.Random, fake: Faker, index: int) -> dict:
    domain_name, domain_code = rng.choice(DOMAINS)
    env = rng.choices(ENVIRONMENTS, weights=[4, 2, 3], k=1)[0]
    criticality = rng.choices(CRITICALITIES, weights=[5, 3, 2], k=1)[0]
    group_type = rng.choices(GROUP_TYPES, weights=[6, 3, 1], k=1)[0]
    purpose = fake.unique.bothify(text="????-####").upper()
    access = {"USR": "USR", "ADM": "ADM", "SEC": "SEC"}[group_type]
    display_name = f"AAD-{domain_code}-{purpose}-{env[:3].upper()}-{access}"
    role_count = rng.choices([1, 2, 3], weights=[7, 2, 1], k=1)[0]
    roles = rng.sample(ROLE_CHOICES, k=role_count)
    group_id = str(uuid.UUID(int=rng.getrandbits(128)))
    subscription = rng.randint(1, 12)
    rg = fake.slug().replace("-", "")[:10] or "shared"
    scope = (
        f"/subscriptions/sub-{domain_code.lower()}-{subscription:03d}"
        if rng.random() < 0.18
        else f"/subscriptions/sub-{domain_code.lower()}-{subscription:03d}/resourceGroups/rg-{rg}-{env}"
    )
    owner_upn = fake.unique.user_name() + "@example.com"
    members_count = rng.randint(1, 250)
    last_review_days = rng.randint(0, 180)
    naming_ok = rng.random() > 0.02

    return {
        "id": group_id,
        "displayName": display_name,
        "memberCount": members_count,
        "roleAssignments": roles,
        "ownerUpn": owner_upn,
        "scope": scope,
        "tags": {
            "env": env,
            "criticality": criticality,
            "cost_center": domain_name[:3],
            "domain": domain_name,
        },
        "namingOk": naming_ok,
        "lastReviewDays": last_review_days,
        "sourceIndex": index,
    }


def generate_dataset(count: int, output_path: Path, seed: int) -> None:
    rng = random.Random(seed)
    fake = Faker()
    Faker.seed(seed)
    fake.unique.clear()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        fh.write('{"value":[\n')
        for idx in range(count):
            row = build_group(rng, fake, idx)
            if idx:
                fh.write(",\n")
            json.dump(row, fh, ensure_ascii=True, separators=(",", ":"))
            if idx and idx % 10000 == 0:
                print(f"generated {idx} groups...", file=sys.stderr)
        fh.write("\n]}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a large fake AAD/Entra-like JSON dataset compatible with /aad/load-groups."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=200000,
        help="Number of groups to generate. Default: 200000",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("fake-aad-groups-200k.json"),
        help="Output JSON file path.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.count <= 0:
        raise SystemExit("--count must be > 0")

    generate_dataset(count=args.count, output_path=args.output, seed=args.seed)
    print(f"Generated {args.count} groups into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
