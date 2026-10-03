import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/detectors/rasp_native_channel.dart';
import 'package:rasp_shield/sdk/lean_session.dart';

/// RaspLeanSession.dispose / start never block a restart (Task 4.9 item 1):
/// dispose does not wait on the event-channel cancel (a root-zone future that
/// never resolves inside a widget test's fake async, which is what made the
/// trial app's "Apply pin" restart hang), and native calls get 2 s.
///
/// Real: RaspLeanSession.start / dispose. Fake: the native method channel
/// (RaspNativeChannel.testInvokeHandler) and the lean-state event stream.
void main() {
  const stateChannel = EventChannel('com.shieldsdk.security/lean_state');

  void fakeNative(WidgetTester tester, Future<Object?> Function(String method) answer) {
    final messenger = tester.binding.defaultBinaryMessenger;
    RaspNativeChannel.testInvokeHandler = (method, arguments) => answer(method);
    messenger.setMockStreamHandler(stateChannel, MockStreamHandler.inline(onListen: (arguments, sink) {}));
    addTearDown(() {
      RaspNativeChannel.testInvokeHandler = null;
      messenger.setMockStreamHandler(stateChannel, null);
    });
  }

  testWidgets('dispose completes without waiting on the event-channel cancel', (tester) async {
    final calls = <String>[];
    fakeNative(tester, (method) async {
      calls.add(method);
      return true;
    });
    final session = await RaspLeanSession.start(const RaspLeanConfig());
    var disposed = false;
    unawaited(session.dispose().then((_) => disposed = true));
    await tester.pump();
    await tester.pump();
    expect(disposed, isTrue);
    expect(calls, ['startLeanSession', 'disposeLeanSession']);
  });

  testWidgets('dispose continues after 2 s when the native stop never answers', (tester) async {
    final neverAnswered = Completer<Object?>();
    fakeNative(tester, (method) => method == 'disposeLeanSession' ? neverAnswered.future : Future.value(true));
    final session = await RaspLeanSession.start(const RaspLeanConfig());
    var disposed = false;
    unawaited(session.dispose().then((_) => disposed = true));
    await tester.pump(const Duration(milliseconds: 1900));
    expect(disposed, isFalse, reason: 'still within the 2 s wait');
    await tester.pump(const Duration(milliseconds: 200));
    expect(disposed, isTrue);
  });

  testWidgets('start returns after 2 s when the native start never answers', (tester) async {
    final neverAnswered = Completer<Object?>();
    fakeNative(tester, (method) => method == 'startLeanSession' ? neverAnswered.future : Future.value(true));
    RaspLeanSession? session;
    unawaited(RaspLeanSession.start(const RaspLeanConfig()).then((s) => session = s));
    await tester.pump(const Duration(milliseconds: 1900));
    expect(session, isNull);
    await tester.pump(const Duration(milliseconds: 200));
    expect(session, isNotNull);
    await session!.dispose();
  });

  testWidgets('a second dispose is a no-op', (tester) async {
    final calls = <String>[];
    fakeNative(tester, (method) async {
      calls.add(method);
      return true;
    });
    final session = await RaspLeanSession.start(const RaspLeanConfig());
    await session.dispose();
    await session.dispose();
    expect(calls.where((m) => m == 'disposeLeanSession'), hasLength(1));
  });
}
