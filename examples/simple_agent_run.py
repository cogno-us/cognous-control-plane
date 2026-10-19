"""Simple agent run example.

Demonstrates the core Agent Control Plane workflow:
- Start a run with an allowed-tool list and a blocked-tool list.
- Add an authority record scoped to 'read'.
- Propose and evaluate a 'crm_read' read action (→ allowed).
- Record reliance on the CRM tool.
- Propose and evaluate an 'email_send' external_send action (→ blocked).
- Complete the run with a final output.
- Export the run record to JSON.
- Generate a replay bundle.

Run from the repository root::

    python examples/simple_agent_run.py
"""

from __future__ import annotations

import pathlib

from agent_control_plane import RunRecorder

OUTPUT_PATH = pathlib.Path("examples/sample_run_record.json")


def main() -> None:
    # ------------------------------------------------------------------ #
    # 1. Start a run                                                       #
    # ------------------------------------------------------------------ #
    recorder = RunRecorder()
    run_id = recorder.start_run(
        task="Summarize a customer record and draft an email.",
        actor="agent-v1",
        environment="production",
        allowed_tools=["crm_read", "notes_search"],
        blocked_tools=["email_send"],
        policy_version="v1.0",
    )
    print(f"Run started  run_id={run_id}")

    # ------------------------------------------------------------------ #
    # 2. Add authority for read (not external_send)                        #
    # ------------------------------------------------------------------ #
    recorder.add_authority_record(
        actor="agent-v1",
        scope=["read"],
        source="user_consent",
    )
    print("Authority record added  scope=['read']")

    # ------------------------------------------------------------------ #
    # 3. Propose crm_read read action → should be allowed                  #
    # ------------------------------------------------------------------ #
    read_action = recorder.propose_action(
        tool_name="crm_read",
        action_type="read",
        target="customer:42",
        payload={"fields": ["name", "email", "account_status"]},
        reason="Retrieve customer details to prepare the summary.",
    )
    read_decision, _ = recorder.evaluate_action(read_action)
    print(
        f"Policy decision  tool=crm_read  result={read_decision.result!r}  "
        f"fingerprint={read_decision.deterministic_fingerprint[:16]}…"
    )

    # ------------------------------------------------------------------ #
    # 4. Record reliance on crm_read                                       #
    # ------------------------------------------------------------------ #
    recorder.record_reliance(
        source_name="crm_read",
        source_type="tool",
        scope="customer record fields: name, email, account_status",
        referenced_action_id=read_action.action_id,
    )
    print("Reliance record added  source=crm_read")

    # ------------------------------------------------------------------ #
    # 5. Propose email_send external_send action → should be blocked       #
    # ------------------------------------------------------------------ #
    send_action = recorder.propose_action(
        tool_name="email_send",
        action_type="external_send",
        target="customer@example.com",
        payload={"subject": "Your account summary", "body": "<draft>"},
        reason="Send the prepared email draft to the customer.",
    )
    send_decision, blocked = recorder.evaluate_action(send_action)
    print(
        f"Policy decision  tool=email_send  result={send_decision.result!r}  "
        f"reason={send_decision.reason}"
    )
    if blocked:
        print(f"Blocked action recorded  blocked_id={blocked.blocked_id}")

    # ------------------------------------------------------------------ #
    # 6. Complete the run                                                   #
    # ------------------------------------------------------------------ #
    recorder.complete_run(
        "Draft prepared but email send blocked pending authorization."
    )
    print("Run completed.")

    # ------------------------------------------------------------------ #
    # 7. Export run record JSON                                             #
    # ------------------------------------------------------------------ #
    out_path = recorder.export_json(OUTPUT_PATH)
    print(f"Run record exported  path={out_path}")

    # ------------------------------------------------------------------ #
    # 8. Generate replay bundle                                             #
    # ------------------------------------------------------------------ #
    bundle = recorder.generate_replay_bundle()
    print(f"Replay bundle generated  replay_bundle_id={bundle.replay_bundle_id}")

    # ------------------------------------------------------------------ #
    # 9. Summary                                                            #
    # ------------------------------------------------------------------ #
    run_record = recorder.to_run_record()
    print("\n--- Run summary ---")
    print(f"  task         : {run_record.task}")
    print(f"  actions      : {len(run_record.actions)}")
    print(f"  decisions    : {len(run_record.decisions)}")
    print(f"  blocked      : {len(run_record.blocked_actions)}")
    print(f"  reliances    : {len(run_record.reliance_records)}")
    print(f"  authority    : {len(run_record.authority_records)}")
    print(f"  final output : {run_record.final_output}")


if __name__ == "__main__":
    main()
