# Cipher-Lens Step-by-Step UI & Feature Evolution Notes

This document maintains a continuous, chronological record of every targeted enhancement and structural adjustment made to Cipher-Lens.

---

## Change 1: Predefined Testing Users, Passwords & Automatic Role Assignment

### 1. Context & Motivation
- Cipher-Lens is in active testing and authorized-lab evaluation.
- Previously, the authentication barrier allowed free-form usernames to manually choose any role (`operator`, `lead_analyst`, `auditor`) from a dropdown, introducing role-spoofing risks and manual friction during testing.

### 2. Implementation Details
1. **Config-Driven User & Password Registry (`config/users.yaml`):**
   - Created a tracked configuration file defining default testing accounts with their designated roles and passwords:
     - **`Harimohan`** $\rightarrow$ **Lead Security Analyst** (`lead_analyst`), password: `leadanalyst123`
     - **`Bhavyaa`** $\rightarrow$ **Operator / Pen-Tester** (`operator`), password: `operator123`
     - **`Yash`** $\rightarrow$ **Security Auditor** (`auditor`), password: `auditor123`
   - Anyone cloning the repository can immediately log in with these defaults or edit `config/users.yaml` to specify custom usernames, roles, and passwords.
2. **Dedicated Auth Module (`src/cipher_lens/ui/auth.py`):**
   - Created `load_user_registry()`, `get_user_by_name()`, and `verify_user_credentials()`.
   - Automatic role resolution: entering a recognized name automatically assigns and locks their role.
   - Enforces constant-time `hmac.compare_digest` password verification.
   - Falls back gracefully to environment tokens (`ADMIN_TOKEN`, `OPERATOR_TOKEN`, `AUDITOR_TOKEN`) for custom usernames or external overrides.
3. **Registration / Access Barrier UI (`src/cipher_lens/ui/app.py`):**
   - Re-styled into a container card displaying active testing accounts.
   - Entering `Harimohan`, `Bhavyaa`, or `Yash` dynamically resolves and displays their role.
4. **Verification & Tests (`tests/ui/test_ui_auth.py`):**
   - Added `test_auth_predefined_users_auto_role` verifying all three role assignments, correct password validation, and wrong password rejection.
