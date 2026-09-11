"""Narrow PreToolUse check for literal private-key headers in supported writes.

Not a general secret scanner; no shell parsing, network calls, logging, or
telemetry. Does not inspect arbitrary Bash writes or subsequent stdin writes.
"""
import json
import re
import sys

PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')
SUPPORTED = {'Write', 'Edit', 'MultiEdit', 'apply_patch'}


def inspect_event(event):
    if not isinstance(event, dict):
        raise ValueError('invalid hook event')
    name = event.get('tool_name')
    if name not in SUPPORTED:
        return {}
    args = event.get('tool_input')
    if not isinstance(args, dict):
        raise ValueError('invalid write input')
    if name == 'Write':
        additions = [args.get('content')]
    elif name == 'Edit':
        additions = [args.get('new_string')]
    elif name == 'MultiEdit':
        edits = args.get('edits')
        if not isinstance(edits, list) or not all(isinstance(e, dict) for e in edits):
            raise ValueError('invalid edits')
        additions = [e.get('new_string') for e in edits]
    else:
        patch = args.get('command', args.get('patch', args.get('input')))
        if not isinstance(patch, str):
            raise ValueError('invalid patch')
        additions = ['\n'.join(line[1:] for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++'))]
    if not all(isinstance(item, str) for item in additions):
        raise ValueError('missing write content')
    if any(PRIVATE_KEY.search(item) for item in additions):
        return {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'permissionDecisionReason': 'A literal private-key header was found in added content. Use a secret reference or an unmistakable placeholder; no key material is included in this message.'}}
    # No allow decision: other host controls still make their own decisions.
    return {}


def main():
    try:
        payload = sys.stdin.buffer.read(1_048_577)
        if len(payload) > 1_048_576:
            raise ValueError('hook input too large')
        result = inspect_event(json.loads(payload))
    except (ValueError, TypeError, RecursionError):
        print('CATpilot write check unavailable: invalid or oversized input. Review before retrying.', file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
