import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Synchronization
import Testing

@testable import AppModels

private final class AccessSigner: AnswerSigner {
  struct State {
    var count = 0
    var ordinary = 0
    var renewals = 0
    var held = false
    var supported = true
    var failure: CompanionKeyError?
    var context: ApprovalAuthentication?
  }
  let state = Mutex(State())
  var canSignAccess: Bool { state.withLock { $0.supported } }
  var count: Int { state.withLock { $0.count } }
  var invalidated: Bool { state.withLock { $0.context?.isCancelled == true } }
  func publicKey() throws -> Data { Data([4] + [UInt8](repeating: 1, count: 64)) }
  func renew() throws -> Data {
    state.withLock { $0.renewals += 1 }
    return try publicKey()
  }
  func sign(_ message: Data, reason: String) async throws -> Data {
    state.withLock { $0.ordinary += 1 }
    return Data("ordinary".utf8)
  }
  func signAccess(_ message: Data, reason: String, authentication: ApprovalAuthentication)
    async throws -> Data
  {
    state.withLock {
      $0.count += 1
      $0.context = authentication
    }
    // Deliberately return even after cancellation: the model must discard stale completion.
    while state.withLock({ $0.held }) { try await Task.sleep(for: .milliseconds(1)) }
    if let error = state.withLock({ $0.failure }) { throw error }
    return Data("fixture-signature".utf8)
  }
}

@MainActor
struct AccessRequestsModelTests {
  private func fixture() async -> (
    PreviewVaultService, AccessSigner, AccessRequestsModel, RelayAccessRequest
  ) {
    let service = PreviewVaultService()
    let signer = AccessSigner()
    let row = PreviewVaultService.sampleAccessRequest()
    await service.setAccessRequests([row])
    let model = AccessRequestsModel(service: service, signers: SharedAnswerSigners(signer: signer))
    await model.refresh()
    return (service, signer, model, row)
  }
  private func started(_ signer: AccessSigner) async {
    for _ in 0..<1000 {
      if signer.count > 0 { return }
      try? await Task.sleep(for: .milliseconds(1))
    }
    Issue.record("The fixture signer did not start")
  }
  @Test func denyDoesNotUseBiometryOrTheAnswerSigner() async {
    let (service, signer, model, row) = await fixture()
    signer.state.withLock { $0.supported = false }
    await model.answer(row, choice: .deny)
    #expect(signer.count == 0)
    #expect(signer.state.withLock { $0.ordinary } == 0)
    let posts = await service.accessPosts()
    #expect(posts.count == 1 && posts[0].signature == nil && posts[0].choice == .deny)
    #expect(model.requests.first?.receipt?.outcome == "denied")
    #expect(model.history.first?.receipt?.outcome == "denied")
  }
  @Test func eachAllowNeedsItsOwnFreshSignerInvocation() async throws {
    let (service, signer, model, row) = await fixture()
    _ = try await signer.sign(Data("unlock".utf8), reason: "unlock")
    await model.answer(row, choice: .allow_once)
    #expect(signer.count == 1 && signer.invalidated)
    let next = PreviewVaultService.sampleAccessRequest(requestID: "82")
    await service.setAccessRequests([next])
    await model.refresh()
    await model.answer(next, choice: .allow_once)
    #expect(signer.count == 2 && signer.invalidated)
    #expect(await service.accessPosts().count == 2)
  }
  @Test func cancellationInvalidatesTheContextAndDiscardsLateCompletion() async {
    let (service, signer, model, row) = await fixture()
    signer.state.withLock { $0.held = true }
    let task = Task { await model.answer(row, choice: .allow_once) }
    await started(signer)
    model.cancel(clear: false)
    #expect(signer.invalidated)
    signer.state.withLock { $0.held = false }
    await task.value
    #expect(await service.accessPosts().isEmpty)
    await model.answer(row, choice: .deny)
    #expect(signer.count == 1)
    #expect(await service.accessPosts().first?.choice == .deny)
  }
  @Test func backgroundOrVaultSwitchNeverPostsALateSignature() async {
    let (service, signer, model, row) = await fixture()
    signer.state.withLock { $0.held = true }
    let task = Task { await model.answer(row, choice: .allow_once) }
    await started(signer)
    model.cancel()
    signer.state.withLock { $0.held = false }
    await task.value
    #expect(signer.invalidated && model.requests.isEmpty)
    #expect(await service.accessPosts().isEmpty)
  }
  @Test func doubleTapCannotStartAnotherMatchOrPost() async {
    let (service, signer, model, row) = await fixture()
    signer.state.withLock { $0.held = true }
    let task = Task { await model.answer(row, choice: .allow_once) }
    await started(signer)
    await model.answer(row, choice: .allow_once)
    #expect(signer.count == 1)
    signer.state.withLock { $0.held = false }
    await task.value
    #expect(await service.accessPosts().count == 1)
  }
  @Test func expiryInvalidatesPendingFaceIDBeforeTheSignerReturns() async {
    let (service, signer, model, _) = await fixture()
    let row = PreviewVaultService.sampleAccessRequest(expiresIn: 2)
    await service.setAccessRequests([row])
    await model.refresh()
    signer.state.withLock { $0.held = true }
    let task = Task { await model.answer(row, choice: .allow_once) }
    await started(signer)
    try? await Task.sleep(for: .seconds(2.1))
    #expect(signer.invalidated)
    #expect(model.busy == nil)
    signer.state.withLock { $0.held = false }
    await task.value
    #expect(await service.accessPosts().isEmpty)
  }
  @Test func taskCancellationInvalidatesTheActualPendingContext() async {
    let (service, signer, model, row) = await fixture()
    signer.state.withLock { $0.held = true }
    let task = Task { await model.answer(row, choice: .allow_once) }
    await started(signer)
    task.cancel()
    #expect(signer.invalidated)
    signer.state.withLock { $0.held = false }
    await task.value
    #expect(await service.accessPosts().isEmpty)
  }
  @Test func unsupportedBiometryEnrollmentFailureAndExpiryFailClosed() async {
    let (service, signer, model, row) = await fixture()
    signer.state.withLock { $0.supported = false }
    await model.answer(row, choice: .allow_once)
    #expect(signer.count == 0 && !model.canAllow(row))
    signer.state.withLock {
      $0.supported = true
      $0.failure = .biometryChanged
    }
    await model.answer(row, choice: .allow_once)
    #expect(signer.invalidated && signer.state.withLock { $0.renewals } == 0)
    #expect(await service.accessPosts().isEmpty)
    let expired = PreviewVaultService.sampleAccessRequest(expiresIn: 0, requestID: "83")
    await service.setAccessRequests([expired])
    await model.refresh()
    #expect(!model.actionable(expired))
    await model.answer(expired, choice: .deny)
    #expect(await service.accessPosts().isEmpty)
  }
  @Test func uncertainTransportRetriesReuseOneSignatureAndNeverExceedThreePosts() async {
    let (service, signer, model, row) = await fixture()
    await service.failNextAccessAnswer(VaultError(.relayUnreachable, "synthetic lost reply"))
    await service.failNextAccessAnswer(VaultError(.relayUnreachable, "synthetic lost reply"))
    await model.answer(row, choice: .allow_once)
    let posts = await service.accessPosts()
    #expect(posts.count == 3 && signer.count == 1)
    #expect(posts.allSatisfy { $0.signature == posts.first?.signature && $0.identity == row.id })
    await model.answer(row, choice: .deny)
    #expect(await service.accessPosts().count == 3)
  }
  @Test func replacingTheExactRowInvalidatesPendingAuthentication() async {
    let (service, signer, model, row) = await fixture()
    signer.state.withLock { $0.held = true }
    let task = Task { await model.answer(row, choice: .allow_once) }
    await started(signer)
    await service.setAccessRequests([
      PreviewVaultService.sampleAccessRequest(requestID: "different")
    ])
    await model.refresh()
    #expect(signer.invalidated)
    signer.state.withLock { $0.held = false }
    await task.value
    #expect(await service.accessPosts().isEmpty)
  }

  @Test func unavailableTransportKeepsFactsReadOnlyAndOffersMacReview() async throws {
    let (service, signer, model, row) = await fixture()
    try await service.lock()
    await model.refresh()
    #expect(model.unavailable != nil)
    #expect(!model.canAllow(row) && !model.actionable(row))
    await model.answer(row, choice: .allow_once)
    #expect(signer.count == 0)
  }

  private func receipt(for row: RelayAccessRequest, outcome: String) -> AccessReceipt {
    AccessReceipt(
      vault_id: row.card.vault_id, team_id: row.card.team_id, qid: row.card.qid,
      request_id: row.card.request_id, asker: row.card.asker.device, digest: row.digest,
      outcome: outcome, answered_by: "another-device", device_name: "Other iPhone",
      device_kind: "iphone", kind: outcome == "denied" ? "deny" : nil,
      at: 100, expires_at: 200)
  }

  @Test func denialOnAnotherDeviceRemainsDeniedAfterTheRequestDeadline() async {
    let (service, signer, model, row) = await fixture()
    let denied = receipt(for: row, outcome: "denied")
    await service.setAccessRequests([
      RelayAccessRequest(
        vault_id: row.vault_id, card: row.card, digest: row.digest, state: "settled",
        receipt: denied, answer_key: row.answer_key)
    ])
    await model.refresh()
    #expect(model.history.first?.receipt?.device_name == "Other iPhone")
    #expect(AccessRequestPresentation.outcome(model.history.first?.receipt) == "Denied")
    let afterDeadline = Date(timeIntervalSince1970: Double(row.card.expires_at) + 1)
    #expect(!AccessRequestPresentation.showsExpiredAccess(denied, at: afterDeadline))
    let posts = await service.accessPosts()
    #expect(signer.count == 0 && posts.isEmpty)
  }

  @Test func deniedAndExpiredReceiptsHaveDifferentHistoryResults() {
    let row = PreviewVaultService.sampleAccessRequest()
    #expect(AccessRequestPresentation.outcome(receipt(for: row, outcome: "denied")) == "Denied")
    #expect(AccessRequestPresentation.outcome(receipt(for: row, outcome: "expired")) == "Access expired")
    #expect(AccessRequestPresentation.outcome(nil) == "Not confirmed")
  }

  @Test func onlyOneAttemptConsentShowsAccessExpiry() {
    let row = PreviewVaultService.sampleAccessRequest()
    let before = Date(timeIntervalSince1970: 199)
    let after = Date(timeIntervalSince1970: 200)
    let once = receipt(for: row, outcome: "allowed_once")
    #expect(!AccessRequestPresentation.showsExpiredAccess(once, at: before))
    #expect(AccessRequestPresentation.showsExpiredAccess(once, at: after))
    for outcome in ["granted_on_mac", "denied", "expired", "invalidated", "future_outcome"] {
      #expect(!AccessRequestPresentation.showsExpiredAccess(receipt(for: row, outcome: outcome), at: after))
    }
  }

  @Test func durableMacGrantsBelongInAllowedHistoryAndOutlastTheRequestDeadline() {
    let row = PreviewVaultService.sampleAccessRequest()
    let grant = receipt(for: row, outcome: "granted_on_mac")
    #expect(AccessRequestPresentation.isAllowed(grant))
    #expect(AccessRequestPresentation.isAllowed(receipt(for: row, outcome: "allowed_once")))
    #expect(AccessRequestPresentation.outcome(grant) == "Durable access granted on the Mac")
    let afterDeadline = Date(timeIntervalSince1970: Double(row.card.expires_at) + 1)
    #expect(!AccessRequestPresentation.showsExpiredAccess(grant, at: afterDeadline))
  }

  @Test func missingAndUnknownOutcomesStayNeutralWithoutAnswerAttribution() {
    let row = PreviewVaultService.sampleAccessRequest()
    let unknown = receipt(for: row, outcome: "future_outcome")
    #expect(AccessRequestPresentation.outcome(unknown) == "Outcome not reported")
    #expect(AccessRequestPresentation.outcome(nil) == "Not confirmed")
    #expect(!AccessRequestPresentation.isAllowed(unknown))
    #expect(!AccessRequestPresentation.isAllowed(nil))
    #expect(AccessRequestPresentation.answerDevice(unknown) == nil)
    #expect(AccessRequestPresentation.answerDevice(nil) == nil)
    #expect(AccessRequestPresentation.answerDevice(receipt(for: row, outcome: "denied")) == "Other iPhone")
  }

}
