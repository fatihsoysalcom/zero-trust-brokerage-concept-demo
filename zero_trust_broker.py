import json

# Represents a trusted entity (e.g., an authenticated user or service)
class TrustedEntity:
    def __init__(self, entity_id, permissions):
        self.entity_id = entity_id
        self.permissions = permissions

    def has_permission(self, required_permission):
        return required_permission in self.permissions

# Represents a resource that needs protection
class ProtectedResource:
    def __init__(self, resource_id, owner_id):
        self.resource_id = resource_id
        self.owner_id = owner_id

    def __str__(self):
        return f"Resource(id={self.resource_id}, owner={self.owner_id})"

# The Zero Trust Broker acts as an intermediary, enforcing access policies
class ZeroTrustBroker:
    def __init__(self):
        self.authorized_entities = {}
        self.resource_access_policies = {}

    def register_entity(self, entity):
        # In a real system, this would involve robust authentication and authorization
        self.authorized_entities[entity.entity_id] = entity
        print(f"[Broker] Registered entity: {entity.entity_id}")

    def define_resource_policy(self, resource_id, required_permission):
        # Policies are defined centrally and enforced by the broker
        self.resource_access_policies[resource_id] = required_permission
        print(f"[Broker] Defined policy for {resource_id}: requires '{required_permission}'")

    def request_access(self, requesting_entity_id, resource_id):
        print(f"\n[Broker] Received access request: Entity '{requesting_entity_id}' for Resource '{resource_id}'")

        # 1. Verify the requesting entity exists and is authenticated (implicit in this demo)
        if requesting_entity_id not in self.authorized_entities:
            print(f"[Broker] Access Denied: Entity '{requesting_entity_id}' not recognized.")
            return False

        requester = self.authorized_entities[requesting_entity_id]

        # 2. Check if a policy exists for the requested resource
        if resource_id not in self.resource_access_policies:
            print(f"[Broker] Access Denied: No policy defined for Resource '{resource_id}'.")
            return False

        required_permission = self.resource_access_policies[resource_id]

        # 3. Enforce the policy: Does the entity have the required permission?
        if requester.has_permission(required_permission):
            print(f"[Broker] Access Granted: Entity '{requesting_entity_id}' has permission '{required_permission}' for Resource '{resource_id}'.")
            return True
        else:
            print(f"[Broker] Access Denied: Entity '{requesting_entity_id}' lacks permission '{required_permission}' for Resource '{resource_id}'.")
            return False

# --- Simulation --- 

broker = ZeroTrustBroker()

# Define some trusted entities
user_admin = TrustedEntity("admin_user_1", ["read", "write", "delete"])
broker.register_entity(user_admin)

user_editor = TrustedEntity("editor_user_2", ["read", "write"])
broker.register_entity(user_editor)

user_viewer = TrustedEntity("viewer_user_3", ["read"])
broker.register_entity(user_viewer)

# Define some protected resources and their access policies
resource_config = ProtectedResource("app_config", "system")
broker.define_resource_policy(resource_config.resource_id, "admin_access")

resource_data = ProtectedResource("user_data", "data_owner")
broker.define_resource_policy(resource_data.resource_id, "read")

resource_sensitive = ProtectedResource("sensitive_report", "finance")
broker.define_resource_policy(resource_sensitive.resource_id, "read")

# Simulate access requests
print("\n--- Access Attempts ---")

# Admin tries to access config (should be denied if not admin_access)
# For simplicity, we'll grant admin_access to admin_user_1 for this specific policy
admin_user_1_with_admin_access = TrustedEntity("admin_user_1", ["read", "write", "delete", "admin_access"])
broker.register_entity(admin_user_1_with_admin_access) # Re-register with added permission
broker.request_access(admin_user_1_with_admin_access.entity_id, resource_config.resource_id)

# Editor tries to access data (should be granted)
broker.request_access(user_editor.entity_id, resource_data.resource_id)

# Viewer tries to access data (should be granted)
broker.request_access(user_viewer.entity_id, resource_data.resource_id)

# Viewer tries to access config (should be denied)
broker.request_access(user_viewer.entity_id, resource_config.resource_id)

# Editor tries to access sensitive report (should be denied if policy is strict)
broker.request_access(user_editor.entity_id, resource_sensitive.resource_id)
