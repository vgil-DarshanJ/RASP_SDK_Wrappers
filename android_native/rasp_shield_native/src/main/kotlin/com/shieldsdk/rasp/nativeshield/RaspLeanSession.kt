package com.shieldsdk.rasp.nativeshield

/**
 * Native facade aliases. The complete polling, timeout and shipping session
 * lives in android-core so Flutter and native hosts execute identical code.
 */
public typealias RaspLeanSession = com.shieldsdk.rasp.RaspLeanSession
public typealias RaspLeanConfig = com.shieldsdk.rasp.RaspLeanConfig
public typealias RaspLeanState = com.shieldsdk.rasp.RaspLeanState
public typealias RaspLeanStateListener = com.shieldsdk.rasp.RaspLeanStateListener
public typealias RaspLocationSnapshot = com.shieldsdk.rasp.RaspLocationSnapshot

// Task 9.3: delivery result of the last location heartbeat
// (RaspLeanState.locationHeartbeat; interval: RaspLeanConfig.locationHeartbeatIntervalMillis).
public typealias RaspLocationHeartbeatStatus = com.shieldsdk.rasp.RaspLocationHeartbeatStatus

// Task 10.0: signed remote configuration (RaspLeanConfig.remoteConfigEnabled,
// remoteManagedDetectors, remoteConfigPollMinutes; RaspLeanState.remoteConfigVersion /
// remoteConfigStatus; RaspLeanSession.refreshRemoteConfigNow()).
public typealias RaspRemoteConfigStatus = com.shieldsdk.rasp.RaspRemoteConfigStatus
public typealias RaspRemoteConfig = com.shieldsdk.rasp.RaspRemoteConfig

// Task 8.1: session risk and transaction API. Call them on RaspLeanSession
// (reportSession, reportTransaction, signTransaction, currentRisk,
// setHighRiskTransactionMode) with RaspLeanConfig.sessionRiskScoring = true —
// the same engine code the Flutter plugin calls.
public typealias RaspSessionEvent = com.shieldsdk.rasp.RaspSessionEvent
public typealias RaspRiskVerdict = com.shieldsdk.rasp.RaspRiskVerdict
public typealias RaspRiskPolicy = com.shieldsdk.rasp.RaspRiskPolicy
public typealias RaspRiskAssessment = com.shieldsdk.rasp.RaspRiskAssessment
public typealias RaspRiskScore = com.shieldsdk.rasp.RaspRiskScore
public typealias RaspSessionReport = com.shieldsdk.rasp.RaspSessionReport
public typealias RaspSignedTransaction = com.shieldsdk.rasp.RaspSignedTransaction
public typealias RaspTransactionReport = com.shieldsdk.rasp.RaspTransactionReport
public typealias RaspAccountHasher = com.shieldsdk.rasp.RaspAccountHasher
