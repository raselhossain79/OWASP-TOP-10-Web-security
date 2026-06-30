# 04 — Framework-Specific Notes

This file breaks down the exact binding mechanism, vulnerable pattern, and correct
mitigation pattern for each major framework where mass assignment commonly appears.
Understanding the mechanism per framework is what lets you predict *where* an
application is likely vulnerable before you've even seen its code — by knowing
which framework conventions are opt-in security boundaries versus secure-by-default.

## 1. Ruby on Rails (ActiveRecord)

### 1.1 The Mechanism

ActiveRecord models historically allowed direct mass assignment via
`Model.new(params)` or `model.update(params)`, which iterates every key in `params`
and calls the matching `attribute=` setter. Modern Rails (4+) requires explicit use
of **Strong Parameters** to opt in to which keys are permitted.

### 1.2 Vulnerable Pattern

```ruby
# Controller action
def create
  @user = User.new(params[:user])  # entire params hash bound directly
  @user.save
end
```

If `params[:user]` includes `{"username" => "x", "isAdmin" => "true"}`, both keys
are written to the `User` object, because `User.new` has no awareness of which
keys originated from the registration form versus which were added by an attacker
editing the raw request body.

### 1.3 Secure Pattern (Strong Parameters)

```ruby
def create
  @user = User.new(user_params)
  @user.save
end

private

def user_params
  params.require(:user).permit(:username, :email, :password)
  # isAdmin is NOT in this list — even if present in the request,
  # .permit() strips any key not explicitly named here
end
```

`permit` implements an **allow-list**: any key not named is silently discarded
before it ever reaches `User.new`. This is the structural fix — the allow-list
lives at the controller boundary, closest to the untrusted input, rather than
relying on the model layer to defend itself.

### 1.4 Why It Still Happens

- Strong parameters must be applied **per controller action**; a developer adding
  a new endpoint (e.g. an admin-bulk-import action) can easily reuse a
  `permit`-list written for a different, narrower context, or skip it entirely
  for an "internal" endpoint that later becomes externally reachable.
  This was effectively the GitHub 2012 incident's structural cause.
- Nested attributes (`accepts_nested_attributes_for`) require their own nested
  `permit` syntax (`permit(:name, address_attributes: [:city, :zip])`); omitting
  the nested allow-list re-opens mass assignment specifically on the nested object,
  even if the top-level object is correctly restricted.

## 2. Django REST Framework (DRF)

### 2.1 The Mechanism

DRF uses **Serializers** to control both serialization (model → JSON) and
deserialization (JSON → model). A serializer's `fields` (or `Meta.fields`)
attribute determines which model fields are exposed for *both* read and write
unless explicitly separated.

### 2.2 Vulnerable Pattern

```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # exposes every model field for read AND write
```

```python
class UserCreateView(generics.CreateAPIView):
    serializer_class = UserSerializer
```

`fields = '__all__'` means any column on the `User` model — including
`is_staff`, `is_superuser`, or a custom `role` field — is both returned in
responses and **writable** through this same serializer. A `POST` body containing
`{"username": "x", "password": "y", "is_staff": true}` is validated and saved
exactly as submitted, because DRF's serializer validation only checks data
*types*, not field-level write permission.

### 2.3 Secure Pattern (Explicit Fields + read_only)

```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'is_staff']
        read_only_fields = ['is_staff']  # accepted in responses, rejected on write
```

Or, more robustly, use **separate serializers** for self-registration versus
admin-managed user creation, so the registration serializer's `Meta.fields` never
lists `is_staff` at all — the field doesn't exist from that serializer's
perspective, so it can't be bound regardless of what the request body contains.

### 2.4 Why It Still Happens

- `fields = '__all__'` is a common shortcut in tutorials and scaffolding tools,
  and frequently survives into production because it "just works" during initial
  development.
- `read_only_fields` is opt-in per serializer; a shared serializer reused across
  an admin viewset and a public viewset can have inconsistent restrictions if the
  admin viewset needs `is_staff` writable and a developer forgets that the same
  serializer class is also used publicly.

## 3. Spring Boot (Java)

### 3.1 The Mechanism

Spring Boot's `@RequestBody` annotation tells Jackson (the JSON library) to
deserialize the incoming JSON directly into the annotated Java object. If that
object is the **JPA entity itself** rather than a dedicated DTO, every field on
the entity — including ones never meant to be client-writable — becomes a valid
JSON key for binding.

### 3.2 Vulnerable Pattern

```java
@Entity
public class User {
    @Id @GeneratedValue
    private Long id;
    private String username;
    private String password;
    private boolean isAdmin;   // internal-only field, but it's part of the entity
    // getters/setters for all fields, including isAdmin
}

@RestController
public class UserController {
    @PostMapping("/api/users")
    public User createUser(@RequestBody User user) {
        return userRepository.save(user);  // entire deserialized entity is persisted
    }
}
```

Because `User` has a public `setIsAdmin(boolean)` setter (required for JPA/Jackson
to work at all), any JSON body containing `"isAdmin": true` is deserialized
directly onto the entity before it's ever saved — Jackson has no concept of which
fields are "meant" to be client-writable; it just matches JSON keys to setter
methods.

### 3.3 Secure Pattern (DTO Separation)

```java
public class UserRegistrationRequest {
    private String username;
    private String password;
    // No isAdmin field exists on this class at all
}

@PostMapping("/api/users")
public User createUser(@RequestBody UserRegistrationRequest request) {
    User user = new User();
    user.setUsername(request.getUsername());
    user.setPassword(passwordEncoder.encode(request.getPassword()));
    // isAdmin is never touched by client input — it defaults to false
    // or is set explicitly by server-side logic only
    return userRepository.save(user);
}
```

The fix is **structural type separation**: the object Jackson deserializes into
(`UserRegistrationRequest`) is a different class from the object that gets
persisted (`User`), and the mapping between them is written explicitly by hand
(or via a mapping library like MapStruct configured with an explicit field list).
Because `isAdmin` doesn't exist on the request DTO, there is no setter for Jackson
to call — the field is structurally unreachable from client input, not just
policy-restricted.

### 3.4 Why It Still Happens

- Binding `@RequestBody` directly to a JPA `@Entity` is faster to write and is a
  pattern shown in many introductory Spring tutorials, making it common in
  early-stage or rapidly-prototyped services that later go to production unchanged.
- Even with DTOs, using a library like ModelMapper or MapStruct in "match by field
  name" auto-mapping mode (rather than an explicit field-by-field mapping) can
  reintroduce mass assignment if the DTO and entity happen to share a field name
  that wasn't intended to be copied.

## 4. Laravel (PHP, Eloquent ORM)

### 4.1 The Mechanism

Eloquent models support mass assignment via `Model::create($data)` or
`$model->fill($data)`, which assigns every key in `$data` to the model unless the
model defines `$fillable` (an allow-list) or `$guarded` (a deny-list).

### 4.2 Vulnerable Pattern

```php
class User extends Model
{
    // No $fillable or $guarded defined — Eloquent defaults to
    // treating $guarded as an empty array, meaning EVERYTHING is mass-assignable
}
```

```php
public function register(Request $request)
{
    $user = User::create($request->all());  // entire request body bound
    return response()->json($user);
}
```

`$request->all()` pulls every input field from the request, and with no
`$fillable`/`$guarded` defined, Eloquent's default is permissive — every column,
including `role` or `is_admin`, is fair game for binding.

### 4.3 Secure Pattern (`$fillable` Allow-List)

```php
class User extends Model
{
    protected $fillable = ['username', 'email', 'password'];
    // role/is_admin intentionally excluded — Eloquent will silently
    // ignore those keys even if present in $request->all()
}
```

`$fillable` is the allow-list equivalent of Rails strong parameters or DRF's
explicit `fields` — only listed attributes can be set via mass assignment methods;
everything else requires explicit `$model->role = 'admin'` assignment in code the
developer controls.

### 4.4 The `$guarded` Trap

Laravel also supports the inverse, a deny-list:

```php
class User extends Model
{
    protected $guarded = ['id'];  // only `id` is protected — EVERYTHING else,
                                    // including role/is_admin, remains mass-assignable
}
```

`$guarded` is a common source of incomplete fixes: a developer protects the
obvious `id` column but forgets to add `role` or `is_admin` to the same list when
those columns are added to the schema later. **Allow-lists (`$fillable`) are
structurally safer than deny-lists (`$guarded`) for exactly this reason** — a new
sensitive column added to the schema is automatically protected under
`$fillable` (since it's not in the list) but automatically *exposed* under
`$guarded` (since it's also not in that list, but `$guarded`'s absence means
"allowed," the opposite default).

### 4.5 Why It Still Happens

- Laravel scaffolding (`php artisan make:model`) does not set `$fillable` by
  default, so it's an easy step to skip under time pressure.
- `$guarded = []` (explicitly empty) is sometimes used during development to
  "just make it work" and never reverted before shipping.

## 5. Cross-Framework Pattern Summary

| Framework | Default behavior without explicit config | Allow-list mechanism |
|---|---|---|
| Rails (ActiveRecord) | Mass assignment via `params` historically open; modern Rails requires it explicitly via controller code | Strong Parameters (`permit`) |
| Django REST Framework | `fields = '__all__'` exposes everything for read+write | Explicit `fields` list + `read_only_fields` |
| Spring Boot | Any class with public setters bound via `@RequestBody` is fully writable | Dedicated request DTOs, separate from persisted entities |
| Laravel (Eloquent) | No `$fillable`/`$guarded` defined = everything mass-assignable | `$fillable` (preferred) over `$guarded` |

The unifying lesson across all four: **the safe default is "nothing is
bindable," and security exists only where a developer has explicitly opted a
field in.** Any framework convenience that flips this default — `fields =
'__all__'`, binding `@RequestBody` straight to an entity, an empty `$guarded`
array, skipping `permit` — reopens the vulnerability class regardless of language.
