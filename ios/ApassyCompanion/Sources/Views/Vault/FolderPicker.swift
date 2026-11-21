import ApassyVaultKit
import SwiftUI

/// A choice of a folder: "No folder" (the top level), then each folder in tree order, indented by
/// its level. The current places have a checkmark. Choosing calls `onPick` and closes the sheet;
/// when the move fails, the sheet stays open with the core's message (the alert of the tabs cannot
/// show above a sheet).
struct FolderPicker: View {
    let title: String
    /// The current places: nil for the top level. A credential may be in several folders; choosing
    /// one of them moves it there alone.
    let selected: Set<String?>
    /// The folders that can be chosen, in tree order (`FolderTree.choices` or `moveTargets`).
    let choices: [FolderChoice]
    /// The name of the top level: "No folder" for a credential, "Top level" for a folder.
    var topLabel = FolderTree.noFolder
    /// The move. Its failure goes to `VaultModel.report`, which `capturingAlert` hands to the sheet.
    let onPick: (String?) async -> Void
    @Environment(VaultModel.self) private var vault
    @Environment(\.dismiss) private var dismiss
    @State private var picking = false
    /// The message of a failed move.
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                if let error { FolderPickerError(message: error) }
                Section {
                    row(nil, name: topLabel, level: 0, symbol: "tray")
                    ForEach(choices) { choice in
                        row(choice.folder.uuid, name: choice.folder.name, level: choice.level, symbol: "folder")
                    }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(role: .cancel) { dismiss() }
                }
            }
            .disabled(picking)
        }
        .interactiveDismissDisabled(picking)
    }

    private func row(_ uuid: String?, name: String, level: Int, symbol: String) -> some View {
        Button {
            guard selected != [uuid] else {
                dismiss()
                return
            }
            picking = true
            error = nil
            Task {
                let failure = await vault.capturingAlert { await onPick(uuid) }
                picking = false
                if let failure {
                    error = failure
                } else {
                    dismiss()
                }
            }
        } label: {
            FolderPickerLabel(
                name: name, level: level, symbol: symbol, top: uuid == nil, checked: selected.contains(uuid))
        }
        .accessibilityAddTraits(selected.contains(uuid) ? .isSelected : [])
    }
}

/// "Add to Folder…": each folder in tree order, a checkmark on the folders of the credential. A tap
/// adds the credential to a folder, or takes it out of a checked one; its other folders stay. The
/// sheet stays open until Done; a failure shows in it.
struct FolderAddPicker: View {
    let item: UInt64
    let choices: [FolderChoice]
    @Environment(VaultModel.self) private var vault
    @Environment(\.dismiss) private var dismiss
    @State private var picking = false
    @State private var error: String?

    var body: some View {
        let current = Set(vault.item(item).map { vault.folderTree.folders(of: $0) } ?? [])
        NavigationStack {
            List {
                if let error { FolderPickerError(message: error) }
                Section {
                    ForEach(choices) { choice in
                        let checked = current.contains(choice.folder.uuid)
                        Button {
                            toggle(choice.folder.uuid, checked: checked)
                        } label: {
                            FolderPickerLabel(
                                name: choice.folder.name, level: choice.level, symbol: "folder", top: false,
                                checked: checked)
                        }
                        .accessibilityAddTraits(checked ? .isSelected : [])
                    }
                }
            }
            .navigationTitle("Add to Folder")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .disabled(picking)
        }
        .interactiveDismissDisabled(picking)
    }

    private func toggle(_ folder: String, checked: Bool) {
        picking = true
        error = nil
        Task {
            error = await vault.capturingAlert {
                if checked {
                    await vault.removeFromFolder(item, folder: folder)
                } else {
                    await vault.addToFolder(item, folder: folder)
                }
            }
            picking = false
        }
    }
}

/// The core's message of a failed change, above the folders of a picker.
private struct FolderPickerError: View {
    let message: String

    var body: some View {
        Section {
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
        }
    }
}

/// A folder in a picker: its symbol and name, indented by its level, and a checkmark.
private struct FolderPickerLabel: View {
    let name: String
    let level: Int
    let symbol: String
    /// The top level, in gray.
    let top: Bool
    let checked: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: symbol)
                .foregroundStyle(top ? Color.secondary : Color.folderTile)
                .accessibilityHidden(true)
            Text(name)
                .foregroundStyle(.primary)
                .lineLimit(1)
            Spacer(minLength: 4)
            if checked {
                Image(systemName: "checkmark")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
            }
        }
        .padding(.leading, CGFloat(level) * 20)
        .contentShape(.rect)
    }
}
