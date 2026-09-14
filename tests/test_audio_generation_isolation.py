from __future__ import annotations

import hashlib
import json
import unittest


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ChunkLedger:
    def __init__(self) -> None:
        self.epoch_by_session: dict[tuple[str, str, str], int] = {}
        self.chunks: dict[tuple[str, str, str, int, int], str] = {}

    def admit(self, *, tenant_id: str, device_id: str, session_id: str, epoch: int, sequence: int, chunk_digest: str) -> None:
        session_key = (tenant_id, device_id, session_id)
        highest_epoch = self.epoch_by_session.get(session_key, epoch)
        if epoch < highest_epoch:
            raise ValueError("stale capture epoch")
        if epoch > highest_epoch:
            self.epoch_by_session[session_key] = epoch
        else:
            self.epoch_by_session.setdefault(session_key, epoch)

        key = (tenant_id, device_id, session_id, epoch, sequence)
        existing = self.chunks.get(key)
        if existing is not None and existing != chunk_digest:
            raise ValueError("same chunk identity with different content")
        self.chunks[key] = chunk_digest



def spectral_artifact_key(*, tenant_id: str, source_audio_id: str, source_revision: int, transform: dict[str, object], content_digest: str) -> str:
    return digest({
        "tenant_id": tenant_id,
        "source_audio_id": source_audio_id,
        "source_revision": source_revision,
        "transform": transform,
        "content_digest": content_digest,
    })


class AudioLifecycle:
    def __init__(self) -> None:
        self.generation: dict[tuple[str, str], int] = {}
        self.deleted: set[tuple[str, str]] = set()
        self.content: dict[tuple[str, str], str] = {}

    def delete(self, tenant_id: str, source_audio_id: str) -> int:
        key = (tenant_id, source_audio_id)
        generation = self.generation.get(key, 0) + 1
        self.generation[key] = generation
        self.deleted.add(key)
        self.content.pop(key, None)
        return generation

    def complete_upload(self, tenant_id: str, source_audio_id: str, generation: int, content_digest: str) -> None:
        key = (tenant_id, source_audio_id)
        current = self.generation.get(key, 0)
        if generation != current or key in self.deleted:
            raise ValueError("stale or tombstoned upload completion")
        self.content[key] = content_digest

    def recreate(self, tenant_id: str, source_audio_id: str) -> int:
        key = (tenant_id, source_audio_id)
        generation = self.generation.get(key, 0) + 1
        self.generation[key] = generation
        self.deleted.discard(key)
        return generation


class AudioGenerationIsolationTests(unittest.TestCase):
    def test_chunk_replay_is_bound_to_device_session_epoch_and_sequence(self) -> None:
        ledger = ChunkLedger()
        common = dict(tenant_id="tenant-a", device_id="device-1", session_id="capture-1", epoch=4, sequence=8)
        ledger.admit(**common, chunk_digest="abc")
        ledger.admit(**common, chunk_digest="abc")
        with self.assertRaises(ValueError):
            ledger.admit(**common, chunk_digest="different")

        ledger.admit(tenant_id="tenant-a", device_id="device-1", session_id="capture-1", epoch=5, sequence=1, chunk_digest="new")
        with self.assertRaises(ValueError):
            ledger.admit(tenant_id="tenant-a", device_id="device-1", session_id="capture-1", epoch=4, sequence=9, chunk_digest="stale")

    def test_cross_device_or_session_chunk_identity_is_distinct(self) -> None:
        ledger = ChunkLedger()
        ledger.admit(tenant_id="tenant-a", device_id="device-1", session_id="s1", epoch=1, sequence=1, chunk_digest="x")
        ledger.admit(tenant_id="tenant-a", device_id="device-2", session_id="s1", epoch=1, sequence=1, chunk_digest="x")
        ledger.admit(tenant_id="tenant-a", device_id="device-1", session_id="s2", epoch=1, sequence=1, chunk_digest="x")
        self.assertEqual(len(ledger.chunks), 3)

    def test_spectral_cache_identity_binds_tenant_revision_and_transform(self) -> None:
        base = dict(source_audio_id="audio-1", source_revision=7, transform={"kind": "stft", "window": 1024, "hop": 256}, content_digest="deadbeef")
        key = spectral_artifact_key(tenant_id="tenant-a", **base)
        self.assertNotEqual(key, spectral_artifact_key(tenant_id="tenant-b", **base))
        self.assertNotEqual(key, spectral_artifact_key(tenant_id="tenant-a", **dict(base, source_revision=8)))
        changed_transform = dict(base)
        changed_transform["transform"] = {"kind": "stft", "window": 2048, "hop": 256}
        self.assertNotEqual(key, spectral_artifact_key(tenant_id="tenant-a", **changed_transform))

    def test_tombstone_generation_blocks_stale_upload_completion(self) -> None:
        lifecycle = AudioLifecycle()
        key = ("tenant-a", "audio-1")
        lifecycle.generation[key] = 3
        deleted_generation = lifecycle.delete(*key)
        self.assertEqual(deleted_generation, 4)
        with self.assertRaises(ValueError):
            lifecycle.complete_upload(*key, generation=3, content_digest="old")
        with self.assertRaises(ValueError):
            lifecycle.complete_upload(*key, generation=4, content_digest="same-generation-but-deleted")
        self.assertNotIn(key, lifecycle.content)

    def test_explicit_recreation_requires_strictly_newer_generation(self) -> None:
        lifecycle = AudioLifecycle()
        key = ("tenant-a", "audio-1")
        lifecycle.generation[key] = 1
        tombstone = lifecycle.delete(*key)
        recreated = lifecycle.recreate(*key)
        self.assertGreater(recreated, tombstone)
        lifecycle.complete_upload(*key, generation=recreated, content_digest="new")
        self.assertEqual(lifecycle.content[key], "new")
        with self.assertRaises(ValueError):
            lifecycle.complete_upload(*key, generation=tombstone, content_digest="stale")


if __name__ == "__main__":
    unittest.main()
