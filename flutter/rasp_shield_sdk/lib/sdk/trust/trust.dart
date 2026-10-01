/// Trust Anchor Engine — the identity half of RASP Shield's client-side
/// defence.
///
/// Where the detectors answer "what is happening to this device?", the trust
/// anchors answer "can this application instance's claimed identity be
/// believed?". The two are independent on purpose: an attacker must defeat
/// both consistently, and inconsistency between them is itself a signal.
///
/// The model — every anchor's source, owner, trust class, legitimate change
/// window and platform limitations — is specified in
/// `docs/TRUST_ANCHOR_MODEL.md`. Read that before changing anything here.
library;

export 'attestation/app_attest.dart';
export 'attestation/attestation_challenge.dart';
export 'attestation/attestation_replay_guard.dart';
export 'attestation/attestation_result.dart';
export 'attestation/attestation_trust.dart';
export 'attestation/play_integrity.dart';
export 'build_identity.dart';
export 'build_identity_collector.dart';
export 'certificate_trust.dart';
export 'certificate_trust_gate.dart';
export 'config_canonical.dart';
export 'config_signing_keys.dart';
export 'configuration_trust.dart';
export 'obfuscation_state.dart';
export 'release_environment.dart';
export 'release_signing.dart';
export 'sdk_integrity.dart';
export 'sdk_version_trust.dart';
export 'signed_config_verifier.dart';
export 'trust_anchor.dart';
export 'trust_assessment.dart';
export 'trust_engine.dart';
export 'trust_evidence.dart';
export 'trust_inputs.dart';
