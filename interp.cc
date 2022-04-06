#include <stdio.h>
#include <stdlib.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <set>
#include <vector>

static void signal_error(const char* message, const char *what) {
  if (what)
    fprintf(stderr, "error: %s: %s\n", message, what);
  else
    fprintf(stderr, "error: %s\n", message);
  exit(1);
}

class Expr {
public:
  enum class Kind { Func, LetRec, Var, Prim, Literal, Call, If };
  
  const Kind kind;

  Expr() = delete;
  virtual ~Expr() {}
  
protected:
  Expr(Kind kind) : kind(kind) {}
};

class Func : public Expr {
public:
  static const uint32_t argCount = 1;
  const std::unique_ptr<Expr> body;
  void *jitCode;

  // FIXME: We need to be able to get to the body from JIT code.  Does this mean
  // we shouldn't be using unique_ptr ?
  static size_t offsetOfBody() { return sizeof(Expr); }
  static size_t offsetOfJitCode() { return offsetOfBody() + sizeof(body); }

  explicit Func(Expr* body)
    : Expr(Kind::Func), body(body), jitCode(nullptr) {}
};

class LetRec : public Expr {
public:
  static const uint32_t argCount = 1;
  const std::unique_ptr<Expr> arg;
  const std::unique_ptr<Expr> body;

  LetRec(Expr* arg, Expr* body)
    : Expr(Kind::LetRec), arg(arg), body(body) {}
};

class Var : public Expr {
public:
  uint32_t depth;

  explicit Var(uint32_t depth)
    : Expr(Kind::Var), depth(depth) {};
};

class Prim : public Expr {
public:
  enum class Op { LessThan, Sub, Add };

  const Op op;
  const std::unique_ptr<Expr> lhs;
  const std::unique_ptr<Expr> rhs;

  Prim(Op op, Expr* lhs, Expr* rhs)
    : Expr(Kind::Prim), op(op), lhs(lhs), rhs(rhs) {};
};

class Literal : public Expr {
public:
  const int32_t val;

  Literal(int32_t val)
    : Expr(Kind::Literal), val(val) {};
};

class Call : public Expr {
public:
  const std::unique_ptr<Expr> func;
  const std::unique_ptr<Expr> arg;

  Call(Expr* func, Expr* arg)
    : Expr(Kind::Call), func(func), arg(arg) {};
};

class If : public Expr {
public:
  const std::unique_ptr<Expr> test;
  const std::unique_ptr<Expr> consequent;
  const std::unique_ptr<Expr> alternate;

  If(Expr *test, Expr* consequent, Expr* alternate)
    : Expr(Kind::If), test(test), consequent(consequent), alternate(alternate) {};
};

class Parser {
  std::vector<std::string> boundVars;

  void pushBound(std::string &&id) { boundVars.push_back(id); }
  void popBound() { boundVars.pop_back(); }
  uint32_t lookupBound(const std::string &id) {
    for (size_t i = 0; i < boundVars.size(); i++)
      if (boundVars[boundVars.size() - i - 1] == id)
        return i;
    signal_error("unbound identifier", id.c_str());
    return -1;
  }

  const char *buf;
  size_t pos;
  size_t len;

  static bool isAlphabetic(char c) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
  }
  static bool isNumeric(char c) {
    return '0' <= c && c <= '9';
  }
  static bool isAlphaNumeric(char c) {
    return isAlphabetic(c) || isNumeric(c);
  }
  static bool isWhitespace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
  }
  
  void error(const char *message) {
    signal_error(message, eof() ? buf : buf + pos);
  }
  bool eof() const { return pos == len; }
  char peek() {
    if (eof()) return '\0';
    return buf[pos];    
  }
  void advance() {
    if (!eof()) pos++;
  }
  char next() {
    char ret = peek();
    advance();
    return ret;
  }
  bool matchChar(char c) {
    if (eof() || peek() != c)
      return false;
    advance();
    return true;
  }
  void skipWhitespace() {
    while (!eof() && isWhitespace(peek()))
      advance();
  }
  bool startsIdentifier() {
    return !eof() && isAlphabetic(peek());
  }
  bool continuesIdentifier() {
    return !eof() && isAlphaNumeric(peek());
  }
  bool matchIdentifier(const char *literal) {
    size_t match_len = std::strlen(literal);
    if (match_len < (len - pos))
      return false;
    if (strncmp(buf + pos, literal, match_len) != 0)
      return false;
    if ((len - pos) < match_len && isAlphaNumeric(buf[pos + match_len]))
      return false;
    pos += match_len;
    return true;
  }
  std::string takeIdentifier() {
    size_t start = pos;
    while (continuesIdentifier())
      advance();
    size_t end = pos;
    return std::string(buf + start, end - start);
  }
  bool matchKeyword(const char *kw) {
    size_t kwlen = std::strlen(kw);
    size_t remaining = len - pos;
    if (remaining < kwlen)
      return false;
    if (strncmp(buf + pos, kw, kwlen) != 0)
      return false;
    pos += kwlen;
    if (!continuesIdentifier())
      return true;
    pos -= kwlen;
    return false;
    if ((len - pos) < kwlen && isalnum(buf[pos + kwlen]))
      return 0;
    pos += kwlen;
    return 1;
  }
  Expr *parsePrim(Prim::Op op) {
    Expr *lhs = parseOne();
    Expr *rhs = parseOne();
    return new Prim(op, lhs, rhs);
  }
  int32_t parseInt32() {
    uint64_t ret = 0;
    while (!eof() && isNumeric(peek())) {
      ret *= 10;
      ret += next() - '0';
      if (ret > 0x7fffffff)
        error("integer too long");
    }
    if (!eof() && !isWhitespace(peek()) && peek() != ')')
      error("unexpected integer suffix");
    return ret;
  }
  Expr *parseOne() {
    skipWhitespace();
    if (eof())
      error("unexpected end of input");
    if (matchChar('(')) {
      skipWhitespace();

      Expr *ret;
      if (matchKeyword("lambda")) {
        skipWhitespace();
        if (!matchChar('('))
          error("expected open paren after lambda");
        skipWhitespace();
        if (!startsIdentifier())
          error("expected an argument for lambda");
        pushBound(takeIdentifier());
        skipWhitespace();
        if (!matchChar(')'))
          error("expected just one argument for lambda");
        Expr *body = parseOne();
        popBound();
        ret = new Func(body);
      } else if (matchKeyword("letrec")) {
        skipWhitespace();
        if (!matchChar('('))
          error("expected open paren after letrec");
        if (!matchChar('('))
          error("expected two open parens after letrec");
        skipWhitespace();
        if (!startsIdentifier())
          error("expected an identifier for letrec");
        pushBound(takeIdentifier());
        skipWhitespace();
        Expr *arg = parseOne();
        if (!matchChar(')'))
          error("expected close paren after letrec binding");
        skipWhitespace();
        if (!matchChar(')'))
          error("expected just one binding for letrec");
        Expr *body = parseOne();
        popBound();
        ret = new LetRec(arg, body);
      } else if (matchKeyword("+")) {
        ret = parsePrim(Prim::Op::Add);
      } else if (matchKeyword("-")) {
        ret = parsePrim(Prim::Op::Sub);
      } else if (matchKeyword("<")) {
        ret = parsePrim(Prim::Op::LessThan);
      } else if (matchKeyword("if")) {
        Expr *test = parseOne();
        Expr *consequent = parseOne();
        Expr *alternate = parseOne();
        ret = new If(test, consequent, alternate);
      } else {
        // Otherwise it's a call.
        Expr *func = parseOne();
        Expr *arg = parseOne();
        ret = new Call(func, arg);
      }
      skipWhitespace();
      if (!matchChar(')'))
        error("expected close parenthesis");
      return ret;
    } else if (startsIdentifier()) {
      return new Var(lookupBound(takeIdentifier()));
    } else if (isNumeric(peek())) {
      return new Literal(parseInt32());
    } else {
      error("unexpected input");
      return nullptr;
    }
  }

public:
  explicit Parser(const char *buf)
    : buf(buf), pos(0), len(strlen(buf)) {}

  Expr *parse() {
    Expr *e = parseOne();
    skipWhitespace();
    if (!eof())
      error("expected end of input after expression");
    return e;
  }
};

static Expr* parse(const char *str) {
  return Parser(str).parse();
}


#define FOR_EACH_HEAP_OBJECT_KIND(M) \
  M(env, Env) \
  M(closure, Closure)

#define DECLARE_CLASS(name, Name) class Name;
FOR_EACH_HEAP_OBJECT_KIND(DECLARE_CLASS)
#undef DECLARE_CLASS

class Heap;

class HeapObject {
public:
  // Any other kind value indicates a forwarded object.
  enum class Kind : uintptr_t {
#define DECLARE_KIND(name, Name) Name,
    FOR_EACH_HEAP_OBJECT_KIND(DECLARE_KIND)
#undef DECLARE_KIND
  };

  static const uintptr_t NotForwardedBit = 1;
  static const uintptr_t NotForwardedBits = 1;
  static const uintptr_t NotForwardedBitMask = (1 << NotForwardedBits) - 1;

protected:
  uintptr_t tag;

  HeapObject(Kind kind)
    : tag((static_cast<uintptr_t>(kind) << NotForwardedBits) | NotForwardedBit) {}

public:
  static size_t offsetOfTag() { return 0; }

  bool isForwarded() const { return (tag & NotForwardedBit) == 0; }
  HeapObject *forwarded() const { return reinterpret_cast<HeapObject*>(tag); }
  void forward(HeapObject *new_loc) { tag = reinterpret_cast<uintptr_t>(new_loc); }

  Kind kind() const { return static_cast<Kind>(tag >> 1); }

#define DEFINE_METHODS(name, Name) \
  bool is##Name() const { return kind() == Kind::Name; } \
  Name* as##Name() { return reinterpret_cast<Name*>(this); }
    FOR_EACH_HEAP_OBJECT_KIND(DEFINE_METHODS)
#undef DEFINE_METHODS

  const char *kindName() const {
    switch (kind()) {
#define RETURN_KIND_NAME(name, Name) case Kind::Name: return #name;
    FOR_EACH_HEAP_OBJECT_KIND(RETURN_KIND_NAME)
#undef RETURN_KIND_NAME
    default:
      signal_error("unexpected heap object kind", nullptr);
      return nullptr;
    }
  }
  inline void* operator new(size_t nbytes, Heap& heap);
};

class Value;

class Heap {
  uintptr_t hp;
  uintptr_t limit;
  uintptr_t base;
  size_t size;
  long count;
  char *mem;

  std::vector<Value> roots;

  static const uintptr_t ALIGNMENT = 8;

  static uintptr_t alignUp(uintptr_t val) {
    return (val + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
  }

  void flip() {
    uintptr_t split = base + (size >> 1);
    if (hp <= split) {
      hp = split;
      limit = base + size;
    } else {
      hp = base;
      limit = split;
    }
    count++;
  }  

  HeapObject* copy(HeapObject *obj);
  size_t scan(HeapObject *obj);

  void visitRoot(Value *root);

  void collect() {
    flip();
    uintptr_t grey = hp;
    for (Value& v : roots)
      visitRoot(&v);
    while(grey < hp)
      grey += alignUp(scan(reinterpret_cast<HeapObject*>(grey)));
  }

public:
  explicit Heap(size_t heap_size) {
    mem = new char[alignUp(heap_size)];
    if (!mem) {
      signal_error("malloc failed", NULL);
    }

    hp = base = reinterpret_cast<uintptr_t>(mem);
    size = heap_size;
    count = -1;
    flip();
  }
  ~Heap() { delete[] mem; }

  static size_t pushRoot(Heap* heap, Value v);
  static Value getRoot(Heap* heap, size_t idx);
  static void setRoot(Heap* heap, size_t idx, Value v);
  static void popRoot(Heap* heap);
  
  template<typename T>
  void visit(T **loc) {
    HeapObject *obj = *loc;
    if (obj != NULL)
      *loc = static_cast<T*>(obj->isForwarded() ? obj->forwarded() : copy(obj));
  }

  inline HeapObject* allocate(size_t size) {
    while (1) {
      uintptr_t addr = hp;
      uintptr_t new_hp = alignUp(addr + size);
      if (limit < new_hp) {
        collect();
        if (limit - hp < size)
          signal_error("ran out of space", NULL);
        continue;
      }
      hp = new_hp;
      return reinterpret_cast<HeapObject*>(addr);
    }
  }
};

inline void* HeapObject::operator new(size_t bytes, Heap& heap) {
  return heap.allocate(bytes);
}

class Value {
  uintptr_t payload;

public:
  static const uintptr_t HeapObjectTag = 0;
  static const uintptr_t SmiTag = 1;
  static const uintptr_t TagBits = 1;
  static const uintptr_t TagMask = (1 << TagBits) - 1;
  
  explicit Value(HeapObject *obj)
    : payload(reinterpret_cast<uintptr_t>(obj)) {}
  explicit Value(intptr_t val)
    : payload((static_cast<uintptr_t>(val) << TagBits) | SmiTag) {}
  
  bool isSmi() const { return (payload & TagBits) == SmiTag; }
  bool isHeapObject() const { return (payload & TagMask) == HeapObjectTag; }
  intptr_t getSmi() const {
    return static_cast<intptr_t>(payload) >> TagBits;
  }
  HeapObject* getHeapObject() {
    return reinterpret_cast<HeapObject*>(payload & ~HeapObjectTag);
  }
  uintptr_t bits() { return payload; }

  const char* kindName() {
    return isSmi() ? "small integer" : getHeapObject()->kindName();
  }

#define DEFINE_METHODS(name, Name) \
  bool is##Name() { return isHeapObject() && getHeapObject()->is##Name(); } \
  Name* as##Name() { return getHeapObject()->as##Name(); }
    FOR_EACH_HEAP_OBJECT_KIND(DEFINE_METHODS)
#undef DEFINE_METHODS

  void visitFields(Heap& heap) {
    if (isHeapObject())
      heap.visit(reinterpret_cast<HeapObject**>(&payload));
  }
};

size_t Heap::pushRoot(Heap* heap, Value v) {
  size_t ret = heap->roots.size();
  heap->roots.push_back(v);
  return ret;
}
Value Heap::getRoot(Heap* heap, size_t idx) {
  return heap->roots[idx];
}
void Heap::setRoot(Heap* heap, size_t idx, Value v) {
  heap->roots[idx] = v;
}
void Heap::popRoot(Heap* heap) { heap->roots.pop_back(); }

template<typename T>
class Rooted {
  Heap& heap;
  size_t idx;
public:
  Rooted(Heap& heap, T* obj) : heap(heap), idx(Heap::pushRoot(&heap, Value(obj))) { }
  ~Rooted() { Heap::popRoot(&heap); }

  T* get() const { return static_cast<T*>(Heap::getRoot(&heap, idx).getHeapObject()); }
  void set(T* obj) { Heap::setRoot(&heap, idx, Value(obj)); }
};

template<>
class Rooted<Value> {
  Heap& heap;
  size_t idx;
public:
  Rooted(Heap& heap, Value obj) : heap(heap), idx(Heap::pushRoot(&heap, obj)) { }
  ~Rooted() { Heap::popRoot(&heap); }

  Value get() const { return Heap::getRoot(&heap, idx); }
  void set(Value obj) { Heap::setRoot(&heap, idx, obj); }
};

class Env : public HeapObject {
public:
  Env *prev;
  Value val;

  static size_t offsetOfPrev() { return sizeof(HeapObject) + 0; }
  static size_t offsetOfVal() { return sizeof(HeapObject) + sizeof(Env*); }

  Env(Rooted<Env> &prev, Rooted<Value> &val)
    : HeapObject(Kind::Env), prev(prev.get()), val(val.get()) {}

  size_t byteSize() { return sizeof(*this); }
  void visitFields(Heap& heap) {
    heap.visit(&prev);
    val.visitFields(heap);
  }

  static Value lookup(Env *env, uint32_t depth) {
    while (depth--)
      env = env->prev;
    return env->val;
  }
};

class Closure : public HeapObject {
public:
  Env *env;
  Func *func;

  static size_t offsetOfEnv() { return sizeof(HeapObject) + 0; }
  static size_t offsetOfFunc() { return sizeof(HeapObject) + sizeof(Env*); }

  Closure(Rooted<Env>& env, Func *func)
    : HeapObject(Kind::Closure), env(env.get()), func(func) {}

  size_t byteSize() { return sizeof(*this); }
  void visitFields(Heap& heap) {
    heap.visit(&env);
  }
};

HeapObject* Heap::copy(HeapObject *obj) {
  size_t size;
  switch (obj->kind()) {
#define COMPUTE_SIZE(name, Name)                                        \
    case HeapObject::Kind::Name:                                        \
      size = obj->as##Name()->byteSize();                               \
      break;
    FOR_EACH_HEAP_OBJECT_KIND(COMPUTE_SIZE)
#undef COMPUTE_SIZE
      }
  HeapObject *new_obj = reinterpret_cast<HeapObject*>(hp);
  memcpy(new_obj, obj, size);
  obj->forward(new_obj);
  hp += alignUp(size);
  return new_obj;
}

size_t Heap::scan(HeapObject *obj) {
  switch (obj->kind()) {
#define SCAN_OBJECT(name, Name)                                         \
    case HeapObject::Kind::Name:                                        \
      obj->as##Name()->visitFields(*this);                              \
      return obj->as##Name()->byteSize();
    FOR_EACH_HEAP_OBJECT_KIND(SCAN_OBJECT)
#undef SCAN_OBJECT
  default:
      abort ();
  }
}

void Heap::visitRoot(Value *root) {
  root->visitFields(*this);
}


static Value
eval_primcall(Prim::Op op, intptr_t lhs, intptr_t rhs) {
  // FIXME: What to do on overflow.
  switch(op) {
  case Prim::Op::LessThan:
    return Value(lhs < rhs);
  case Prim::Op::Add:
    return Value(lhs + rhs);
  case Prim::Op::Sub:
    return Value(lhs - rhs);
  default:
    signal_error("unexpected primcall op", nullptr);
    return Value(nullptr);
  }
}

static std::set<Func*> jitCandidates;

static Value
eval(Expr *expr, Env* unrooted_env, Heap& heap) {
  Rooted<Env> env(heap, unrooted_env);
  
tail:
  switch (expr->kind) {
  case Expr::Kind::Func: {
    Func *func = static_cast<Func*>(expr);
    jitCandidates.insert(func);
    return Value(new(heap) Closure(env, func));
  }
  case Expr::Kind::Var: {
    Var *var = static_cast<Var*>(expr);
    return Env::lookup(env.get(), var->depth);
  }
  case Expr::Kind::Prim: {
    Prim *prim = static_cast<Prim*>(expr);
    Value lhs = eval(prim->lhs.get(), env.get(), heap);
    if (!lhs.isSmi())
      signal_error("primcall expected integer lhs, got", lhs.kindName());
    Value rhs = eval(prim->rhs.get(), env.get(), heap);
    if (!rhs.isSmi())
      signal_error("primcall expected integer rhs, got", rhs.kindName());
    return eval_primcall(prim->op, lhs.getSmi(), rhs.getSmi());
  }
  case Expr::Kind::Literal: {
    Literal *literal = static_cast<Literal*>(expr);
    return Value(literal->val);
  }
  case Expr::Kind::Call: {
    {
      Call *call = static_cast<Call*>(expr);
      Rooted<Value> func(heap, eval(call->func.get(), env.get(), heap));
      if (!func.get().isClosure())
        signal_error("call expected closure, got", func.get().kindName());
      Rooted<Value> arg(heap, eval(call->arg.get(), env.get(), heap));
      Closure *closure = func.get().asClosure();
      expr = closure->func->body.get();
      Rooted<Env> closure_env(heap, closure->env);
      env.set(new(heap) Env(closure_env, arg));
    }
    goto tail;
  }
  case Expr::Kind::LetRec: {
    LetRec *letrec = static_cast<LetRec*>(expr);
    {
      Rooted<Value> filler(heap, Value(intptr_t(0)));
      env.set(new(heap) Env(env, filler));
    }
    Value arg = eval(letrec->arg.get(), env.get(), heap);
    env.get()->val = arg;
    expr = letrec->body.get();
    goto tail;
  }
  case Expr::Kind::If: {
    If *if_ = static_cast<If*>(expr);
    Value test = eval(if_->test.get(), env.get(), heap);
    if (!test.isSmi())
      signal_error("if expected integer, got", test.kindName());
    expr = test.getSmi() ? if_->consequent.get() : if_->alternate.get();
    goto tail;
  }
  default:
    signal_error("unexpected expr kind", nullptr);
    return Value(nullptr);
  }
}

// WebAssembly type encodings are all single-byte negative SLEB128s, hence:
//  forall tc:TypeCode. ((tc & SLEB128SignMask) == SLEB128SignBit
static const uint8_t SLEB128SignMask = 0xc0;
static const uint8_t SLEB128SignBit = 0x40;

enum class WasmSimpleBlockType : uint8_t {
  Void = 0x40,  // SLEB128(-0x40)
};

enum class WasmValType : uint8_t {
  I32 = 0x7f,     // SLEB128(-0x01)
  I64 = 0x7e,     // SLEB128(-0x02)
  F32 = 0x7d,     // SLEB128(-0x03)
  F64 = 0x7c,     // SLEB128(-0x04)
  FuncRef = 0x70, // SLEB128(-0x10)
};

using WasmResultType = std::vector<WasmValType>;
struct WasmFuncType {
  const WasmResultType params;
  const WasmResultType results;
};

struct WasmFunc {
  size_t typeIdx;
  const std::vector<WasmValType> locals;
  const std::vector<uint8_t> code;
};

struct WasmWriter {
  std::vector<uint8_t> code;

  std::vector<uint8_t> finish() { return code; }
  void emit(uint8_t byte) { code.push_back(byte); }

  void emitVarU32(uint32_t i) {
    do {
      uint8_t byte = i & 0x7f;
      i >>= 7;
      if (i != 0)
        byte |= 0x80;
      emit(byte);
    } while (i != 0);
  }
  void emitVarI32(int32_t i) {
    bool done;
    do {
      uint8_t byte = i & 0x7f;
      i >>= 7;
      done = ((i == 0) && !(byte & 0x40)) || ((i == -1) && (byte & 0x40));
      if (!done)
        byte |= 0x80;
      emit(byte);
    } while (!done);
  }

  size_t emitPatchableVarU32() {
    size_t offset = code.size();
    emitVarU32(UINT32_MAX);
    return offset;
  }
  size_t emitPatchableVarI32() {
    size_t offset = code.size();
    emitVarI32(INT32_MAX);
    return offset;
  }
  void patchVarI32(size_t offset, int32_t val) {
    for (size_t i = 0; i < 5; i++, val >>= 7) {
      uint8_t byte = val & 0x7f;
      if (i < 4)
        byte |= 0x80;
      code[offset + i] = byte;
    }
  }
  void patchVarU32(size_t offset, uint32_t val) {
    for (size_t i = 0; i < 5; i++, val >>= 7) {
      uint8_t byte = val & 0x7f;
      if (i < 4)
        byte |= 0x80;
      code[offset + i] = byte;
    }
  }
  void emitValType(WasmValType t) { emit(static_cast<uint8_t>(t)); }
};

struct WasmAssembler : public WasmWriter {
  enum class Op : uint8_t {
    Unreachable = 0x00,
    Nop = 0x01,
    Block = 0x02,
    Loop = 0x03,
    If = 0x04,
    Else = 0x05,
    End = 0x0b,
    Br = 0x0c,
    BrIf = 0x0d,
    Return = 0x0f,

    // Call operators
    Call = 0x10,
    CallIndirect = 0x11,

    // Parametric operators
    Drop = 0x1a,

    // Variable access
    LocalGet = 0x20,
    LocalSet = 0x21,
    LocalTee = 0x22,

    // Memory-related operators
    I32Load = 0x28,
    I32Store = 0x36,

    // Constants
    I32Const = 0x41,

    // Comparison operators
    I32Eqz = 0x45,
    I32Eq = 0x46,
    I32Ne = 0x47,
    I32LtS = 0x48,
    I32LtU = 0x49,

    // Numeric operators
    I32Add = 0x6a,
    I32Sub = 0x6b,
    I32And = 0x71,
    I32Or = 0x72,
    I32Xor = 0x73,
    I32Shl = 0x74,
    I32ShrS = 0x75,
    I32ShrU = 0x76,
  };
  void emitOp(Op op) { emit(static_cast<uint8_t>(op)); }

  size_t emitPatchableI32Const() {
    emitOp(Op::I32Const);
    return emitPatchableVarI32();
  }
  void emitI32Const(int32_t val) {
    emitOp(Op::I32Const);
    emitVarI32(val);
  }
  void emitMemArg(uint32_t align, uint32_t offset) {
    emitVarU32(align);
    emitVarU32(offset);
  }
  static const uint32_t Int32SizeLog2 = 2;
  void emitI32Load(uint32_t offset = 0) {
    // Base address on stack.
    emitOp(Op::I32Load);
    emitMemArg(Int32SizeLog2, offset);
  }
  void emitI32Store(uint32_t offset = 0) {
    // Base address and value to store on stack.
    emitOp(Op::I32Store);
    emitMemArg(Int32SizeLog2, offset);
  }

  void emitLocalGet(uint32_t idx) {
    emitOp(Op::LocalGet);
    emitVarU32(idx);
  }
  void emitLocalSet(uint32_t idx) {
    emitOp(Op::LocalSet);
    emitVarU32(idx);
  }
  void emitLocalTee(uint32_t idx) {
    emitOp(Op::LocalTee);
    emitVarU32(idx);
  }

  void emitI32Eqz() { emitOp(Op::I32Eqz); }
  void emitI32Eq() { emitOp(Op::I32Eq); }
  void emitI32Ne() { emitOp(Op::I32Ne); }
  void emitI32LtS() { emitOp(Op::I32LtS); }
  void emitI32LtU() { emitOp(Op::I32LtU); }

  void emitI32Add() { emitOp(Op::I32Add); }
  void emitI32Sub() { emitOp(Op::I32Sub); }
  void emitI32And() { emitOp(Op::I32And); }
  void emitI32Or() { emitOp(Op::I32Or); }
  void emitI32Xor() { emitOp(Op::I32Xor); }
  void emitI32Shl() { emitOp(Op::I32Shl); }
  void emitI32ShrS() { emitOp(Op::I32ShrS); }
  void emitI32ShrU() { emitOp(Op::I32ShrU); }

  void emitCallIndirect(uint32_t calleeType, uint32_t table = 0) {
    emitOp(Op::CallIndirect);
    emitVarU32(calleeType);
    emitVarU32(table);
  }

  void emitBlock() {
    emitOp(Op::Block);
    emit(static_cast<uint8_t>(WasmSimpleBlockType::Void));
  }
  void emitBlock(WasmValType blockType) {
    emitOp(Op::Block);
    emit(static_cast<uint8_t>(blockType));
  }
  void emitEnd() { emitOp(Op::End); }

  void emitBr(uint32_t offset) {
    emitOp(Op::Br);
    emitVarU32(offset);
  }
  void emitBrIf(uint32_t offset) {
    emitOp(Op::BrIf);
    emitVarU32(offset);
  }
  void emitUnreachable() {
    emitOp(Op::Unreachable);
  }
  void emitReturn() {
    emitOp(Op::Return);
  }
};
  
struct WasmModuleWriter : WasmWriter {
  enum class SectionId : uint8_t {
    Custom = 0,
    Type = 1,
    Import = 2,
    Function = 3,
    Table = 4,
    Memory = 5,
    Global = 6,
    Export = 7,
    Start = 8,
    Elem = 9,
    Code = 10,
    Data = 11,
    DataCount = 12,
  };

  enum class DefinitionKind : uint8_t {
    Function = 0x00,
    Table = 0x01,
    Memory = 0x02,
    Global = 0x03,
  };

  enum class LimitsFlags : uint8_t {
    Default = 0x0,
    HasMaximum = 0x1,
    IsShared = 0x2,
    IsI64 = 0x4,
  };

  void emitMagic() {
    emit(0x00); emit(0x61); emit(0x73); emit(0x6D);
  }
  void emitVersion() {
    emit(0x01); emit(0x00); emit(0x00); emit(0x00);
  }
  void emitResultType(const WasmResultType &type) {
    emitVarU32(type.size());
    for (WasmValType t : type)
      emitValType(t);
  }
  void emitSectionId(SectionId id) { emit(static_cast<uint8_t>(id)); }
  void emitTypeSection(const std::vector<WasmFuncType> &types) {
    emitSectionId(SectionId::Type);
    size_t patchLoc = emitPatchableVarU32();
    size_t start = code.size();
    emitVarU32(types.size());
    for (const auto& type : types) {
      emit(0x60); // Type constructor for function types.
      emitResultType(type.params);
      emitResultType(type.results);
    }
    patchVarU32(patchLoc, code.size() - start);
  }
  void emitName(const char *name) {
    emitVarU32(strlen(name));
    while (*name)
      emit(*name++);
  }
  void emitImportSection() {
    emitSectionId(SectionId::Import);
    size_t patchLoc = emitPatchableVarU32();
    size_t start = code.size();
    // Twp imports: the memory and the indirect call table.
    emitVarU32(2);
    emitName("env");
    emitName("memory");
    emit(static_cast<uint8_t>(DefinitionKind::Memory));
    emit(static_cast<uint8_t>(LimitsFlags::Default));
    emitVarU32(0);
    emitName("env");
    emitName("indirect_call_table");
    emit(static_cast<uint8_t>(DefinitionKind::Table));
    emitValType(WasmValType::FuncRef);
    emit(static_cast<uint8_t>(LimitsFlags::Default));
    emitVarU32(0);
    patchVarU32(patchLoc, code.size() - start);
  }
  void emitFunctionSection(const std::vector<WasmFunc> &funcs) {
    emitSectionId(SectionId::Function);
    size_t patchLoc = emitPatchableVarU32();
    size_t start = code.size();
    emitVarU32(funcs.size());
    for (const auto& func : funcs)
      emitVarU32(func.typeIdx);
    patchVarU32(patchLoc, code.size() - start);
  }
  std::vector<uint8_t> encodeLocals(const std::vector<WasmValType> &locals) {
    uint32_t runs = 0;
    {
      size_t local = 0;
      while (local < locals.size()) {
        WasmValType t = locals[local++];
        while (local < locals.size() && locals[local] == t)
          local++;
        runs++;
      }
    }
    WasmWriter writer;
    writer.emitVarU32(runs);
    {
      size_t local = 0;
      while (local < locals.size()) {
        WasmValType t = locals[local++];
        uint32_t count = 1;
        while (local < locals.size() && locals[local] == t)
          count++, local++;
        writer.emitVarU32(count);
        writer.emitValType(t);
      }
    }
    return writer.finish();
  }
  void emitCodeSection(const std::vector<WasmFunc> &funcs) {
    emitSectionId(SectionId::Code);
    size_t patchLoc = emitPatchableVarU32();
    size_t start = code.size();
    emitVarU32(funcs.size());
    for (const auto& func : funcs) {
      std::vector<uint8_t> locals = encodeLocals(func.locals);
      emitVarU32(locals.size() + func.code.size());
      code.insert(code.end(), locals.begin(), locals.end());
      code.insert(code.end(), func.code.begin(), func.code.end());
    }
    patchVarU32(patchLoc, code.size() - start);
  }
};

struct WasmModuleBuilder {
  std::vector<WasmFuncType> types;
  std::vector<WasmFunc> functions;
  // std::vector<Reloc> relocs;

  size_t internFuncType(const WasmResultType& params,
                        const WasmResultType& results) {
    for (size_t i = 0; i < types.size(); i++) {
      if (types[i].params.size() != params.size())
        continue;
      if (types[i].results.size() != results.size())
        continue;
      bool same = true;
      for (size_t j = 0; j < params.size(); j++)
        if (types[i].params[i] != params[i])
          same = false;
      for (size_t j = 0; j < results.size(); j++)
        if (types[i].results[i] != results[i])
          same = false;
      if (same)
        return i;
    }
    types.push_back(WasmFuncType{params, results});
    return types.size() - 1;
  }

  size_t addFunction(uint32_t type, std::vector<WasmValType> locals,
                     std::vector<uint8_t>&& code) {
    functions.push_back(WasmFunc{type, locals, code});
    return functions.size() - 1;
  }
  
  std::vector<uint8_t> finish() {
    WasmModuleWriter writer;
    writer.emitMagic();
    writer.emitVersion();
    writer.emitTypeSection(types);
    writer.emitImportSection();
    writer.emitFunctionSection(functions);
    writer.emitCodeSection(functions);
    return writer.finish();
  }
};

struct VMCall {
  static void* Allocate(Heap* heap, size_t bytes) {
    return heap->allocate(bytes);
  }
  static size_t PushRoot(Heap* heap, Value v) {
    return Heap::pushRoot(heap, v);
  }
  static Value GetRoot(Heap* heap, size_t idx) {
    return Heap::getRoot(heap, idx);
  }
  static void PopRoots(Heap* heap, size_t n) {
    while (n--)
      Heap::popRoot(heap);
  }
  static void Error(const char *msg, const char *what) {
    signal_error(msg, what);
  }
  static Value Eval(Expr *expr, Env *env, Heap *heap) {
    return eval(expr, env, *heap);
  }
};

struct VMCallTypes {
  bool initialized = false;
  uint32_t Allocate;
  uint32_t PushRoot;
  uint32_t GetRoot;
  uint32_t PopRoots;
  uint32_t Error;
  uint32_t Eval;
  uint32_t JitCall;
};

struct WasmMacroAssembler : public WasmAssembler {
  WasmModuleBuilder moduleBuilder;
  VMCallTypes vmCallTypes;
  size_t maxRoots;
  size_t currentRootCount;
  size_t currentActiveLocals;
  std::vector<WasmValType> locals;

  static const uint32_t UnrootedEnvLocalIdx = 0;
  static const uint32_t HeapLocalIdx = 1;
  static const uint32_t ParamCount = 2;

  size_t acquireLocal(WasmValType type = WasmValType::I32) {
    for (size_t i = currentActiveLocals; i < locals.size(); i++) {
      if (locals[i] == type) {
        size_t idx = ParamCount + i;
        currentActiveLocals = i + 1;
        return idx;
      }
    }
    locals.push_back(type);
    currentActiveLocals = ParamCount + locals.size();
    return currentActiveLocals - 1;
  }
  void releaseLocal() { currentActiveLocals--; }
  void releaseLocals(size_t n) { while (n--) releaseLocal(); }
      
  void emitLoadPointer(size_t offset = 0) { emitI32Load(offset); }
  void emitStorePointer(size_t offset = 0) { emitI32Store(offset); }


  void emitUnrootedEnv() { emitLocalGet(UnrootedEnvLocalIdx); }
  void emitHeap() { emitLocalGet(HeapLocalIdx); }

  template<typename T>
  void emitVMCall(T f, uint32_t type) {
    emitI32Const(reinterpret_cast<intptr_t>(f));
    emitCallIndirect(type); // Sad panda that it's indirect!
  }

  template<typename T>
  void emitAllocate() {
    size_t bytes = sizeof(T);
    emitHeap();
    emitI32Const(bytes);
    emitVMCall(&VMCall::Allocate, vmCallTypes.Allocate);
  }
  
  // Return index of local, which stores index into root vector.
  uint32_t emitStoreGCRoot() {
    currentRootCount++;
    if (maxRoots < currentRootCount)
      maxRoots = currentRootCount;
    uint32_t local = acquireLocal();
    emitLocalTee(local);
    emitHeap();
    emitVMCall(&VMCall::PushRoot, vmCallTypes.PushRoot);
    return local;
  }
  void emitLoadGCRoot(uint32_t local) {
    emitHeap();
    emitLocalGet(local);
    emitVMCall(&VMCall::GetRoot, vmCallTypes.GetRoot);
  }
  void emitPopGCRootsAndReleaseLocals(size_t n) {
    currentRootCount -= n;
    releaseLocals(n);
    emitHeap();
    emitI32Const(n);
    emitVMCall(&VMCall::PopRoots, vmCallTypes.PopRoots);
  }
    
  void emitHeapObjectInitTag(HeapObject::Kind kind) {
    uintptr_t val = static_cast<uintptr_t>(kind);
    val <<= HeapObject::NotForwardedBits;
    val |= HeapObject::NotForwardedBit;
    emitI32Const(val);
    emitStorePointer(HeapObject::offsetOfTag());
  }

  void emitPushConstantPointer(const void *ptr) {
    emitI32Const(reinterpret_cast<intptr_t>(ptr));
  }

  void emitAssertionFailure(const char *msg, const char *what) {
    emitPushConstantPointer(msg);
    emitPushConstantPointer(what);
    emitVMCall(&VMCall::Error, vmCallTypes.Error);
    emitUnreachable();
  }

  void emitCheckSmi(size_t localIdx, const char *what) {
    emitBlock();
    emitLocalGet(localIdx);
    emitI32Const(Value::TagMask);
    emitI32And();
    emitI32Const(Value::SmiTag);
    emitI32Eq();
    emitBrIf(0);
    emitAssertionFailure("expected an integer", what);
    emitEnd();
  }
  void emitValueToSmi() {
    emitI32Const(Value::TagBits);
    emitI32ShrS();
  }
  void emitSmiToValue() {
    emitI32Const(Value::TagBits);
    emitI32Shl();
    emitI32Const(Value::SmiTag);
    emitI32Or();
  }
  
  // These three functions rely on Value::HeapObjectTag == 0.
  void emitCheckHeapObject(size_t localIdx, HeapObject::Kind kind,
                           const char *what) {
    emitBlock();
    emitLocalGet(localIdx);
    emitI32Const(Value::TagMask);
    emitI32And();
    emitI32Eqz();
    emitBrIf(0);
    emitAssertionFailure("expected an heap object", what);
    emitEnd();

    emitBlock();
    emitLocalGet(localIdx);
    emitLoadPointer();
    emitI32Const(HeapObject::NotForwardedBits);
    emitI32ShrU();
    emitI32Const(static_cast<int32_t>(kind));
    emitI32Eq();
    emitBrIf(0);
    emitAssertionFailure("expected a different heap object kind", what);
    emitEnd();
  }
  void emitValueToHeapObject() {}
  void emitHeapObjectToValue() {}

  void initializeVMCallTypes() {
    size_t Call_2_1 = moduleBuilder.internFuncType(
        {WasmValType::I32, WasmValType::I32}, {WasmValType::I32});
    size_t Call_2_0 = moduleBuilder.internFuncType(
        {WasmValType::I32, WasmValType::I32}, {});
    size_t Call_3_1 = moduleBuilder.internFuncType(
        {WasmValType::I32, WasmValType::I32, WasmValType::I32}, {WasmValType::I32});
    vmCallTypes.Allocate = Call_2_1; // Heap, size -> void*
    vmCallTypes.PushRoot = Call_2_1; // Heap, V -> idx
    vmCallTypes.GetRoot = Call_2_1;  // Heap, idx -> V
    vmCallTypes.PopRoots = Call_2_0; // Heap, n -> ()
    vmCallTypes.Error = Call_2_0; // Heap, n -> ()
    vmCallTypes.Eval = Call_3_1; // Expr, Env, Heap -> Val
    vmCallTypes.JitCall = Call_2_1; // Env, Heap -> Val
    
    vmCallTypes.initialized = true;
  }

  void beginFunction() {
    if (!vmCallTypes.initialized)
      initializeVMCallTypes();

    maxRoots = currentRootCount = currentActiveLocals = 0;
    locals.clear();
    code.clear();
  }

  uint32_t endFunction() {
    emitReturn();
    emitEnd();
    return moduleBuilder.addFunction(vmCallTypes.JitCall, locals, finish());
  }

  std::vector<uint8_t> endModule() {
    return moduleBuilder.finish();
  }
};

class WasmCompiler {
  WasmMacroAssembler masm;
  
  void compile(Expr *expr, size_t envRoot) {
    switch (expr->kind) {
    case Expr::Kind::Func: {
      Func *func = static_cast<Func*>(expr);
      masm.emitAllocate<Closure>();
      size_t local = masm.acquireLocal();
      masm.emitLocalTee(local);
      masm.emitHeapObjectInitTag(HeapObject::Kind::Closure);
      masm.emitLocalGet(local);
      masm.emitLoadGCRoot(envRoot);
      masm.emitStorePointer(Closure::offsetOfEnv());
      masm.emitLocalGet(local);
      masm.emitPushConstantPointer(func);
      masm.emitStorePointer(Closure::offsetOfFunc());
      masm.emitLocalGet(local);
      masm.releaseLocal();
      return;
    }
    case Expr::Kind::Var: {
      Var *var = static_cast<Var*>(expr);
      masm.emitLoadGCRoot(envRoot);
      for (auto depth = var->depth; depth; depth--)
        masm.emitLoadPointer(Env::offsetOfPrev());
      masm.emitLoadPointer(Env::offsetOfVal());
      return;
    }
    case Expr::Kind::Prim: {
      Prim *prim = static_cast<Prim*>(expr);
      compile(prim->lhs.get(), envRoot);
      uint32_t lhs = masm.acquireLocal();
      masm.emitLocalSet(lhs);
      masm.emitCheckSmi(lhs, "primcall");
      compile(prim->rhs.get(), envRoot);
      uint32_t rhs = masm.acquireLocal();
      masm.emitLocalSet(rhs);
      masm.emitCheckSmi(rhs, "primcall");
      
      masm.emitLocalGet(lhs);
      masm.emitValueToSmi();
      masm.emitLocalGet(rhs);
      masm.emitValueToSmi();
      switch(prim->op) {
      case Prim::Op::LessThan: masm.emitI32LtS(); break;
      case Prim::Op::Add:      masm.emitI32Add(); break;
      case Prim::Op::Sub:      masm.emitI32Sub(); break;
      default:
        abort();
      }
      masm.emitSmiToValue();
      masm.releaseLocals(2);
      return;
    }
    case Expr::Kind::Literal: {
      Literal *literal = static_cast<Literal*>(expr);
      Value v(literal->val);
      masm.emitI32Const(v.bits());
      return;
    }
    case Expr::Kind::Call: {
      Call *call = static_cast<Call*>(expr);
      compile(call->func.get(), envRoot);

      uint32_t unrootedCallee = masm.acquireLocal();
      uint32_t unrootedEnv = masm.acquireLocal();

      masm.emitLocalSet(unrootedCallee);
      masm.emitCheckHeapObject(unrootedCallee, HeapObject::Kind::Closure,
                               "call");
      masm.emitLocalGet(unrootedCallee);
      uint32_t callee = masm.emitStoreGCRoot();
      compile(call->arg.get(), envRoot);
      uint32_t arg = masm.emitStoreGCRoot();
      masm.emitAllocate<Env>();
      // unrootedCallee now invalid.

      masm.emitLocalTee(unrootedEnv);
      masm.emitHeapObjectInitTag(HeapObject::Kind::Env);
      masm.emitLocalGet(unrootedEnv);
      masm.emitLoadGCRoot(envRoot);
      masm.emitStorePointer(Env::offsetOfPrev());
      masm.emitLocalGet(unrootedEnv);
      masm.emitLoadGCRoot(arg);
      masm.emitStorePointer(Env::offsetOfVal());

      masm.emitLoadGCRoot(callee);
      masm.emitLocalSet(unrootedCallee);
      masm.emitPopGCRootsAndReleaseLocals(2);
      // Now unrootedEnv and unrootedCallee valid, gcroots popped.
      
      masm.emitBlock(WasmValType::I32);
      masm.emitBlock();
      masm.emitLocalGet(unrootedCallee);
      masm.emitLoadPointer(Closure::offsetOfFunc());
      masm.emitLoadPointer(Func::offsetOfJitCode());
      // If there is jit code, jump out.
      masm.emitBrIf(0);
      
      // No jit code?  Call eval.  FIXME: tail calls.
      masm.emitLocalGet(unrootedCallee);
      masm.emitLoadPointer(Closure::offsetOfFunc());
      masm.emitLoadPointer(Func::offsetOfBody());
      masm.emitLocalGet(unrootedEnv);
      masm.emitHeap();
      masm.emitVMCall(&VMCall::Eval, masm.vmCallTypes.Eval);
      masm.emitBr(1); // Called eval, jump past jit call with result.
      masm.emitEnd();

      // Otherwise if we get here there's JIT code.
      masm.emitLocalGet(unrootedEnv);
      masm.emitHeap();
      masm.emitLocalGet(unrootedCallee);
      masm.emitLoadPointer(Closure::offsetOfFunc());
      masm.emitLoadPointer(Func::offsetOfJitCode());
      masm.emitCallIndirect(masm.vmCallTypes.JitCall);
      masm.emitEnd();

      masm.releaseLocals(2);
      return;
    }
    case Expr::Kind::LetRec: {
      LetRec *letrec = static_cast<LetRec*>(expr);
      masm.emitAllocate<Env>();
      {
        uint32_t unrootedEnv = masm.acquireLocal();
        masm.emitLocalTee(unrootedEnv);
        masm.emitHeapObjectInitTag(HeapObject::Kind::Env);
        masm.emitLocalGet(unrootedEnv);
        masm.emitLoadGCRoot(envRoot);
        masm.emitStorePointer(Env::offsetOfPrev());
        masm.emitLocalGet(unrootedEnv);
        masm.emitI32Const(Value(intptr_t(0)).bits());
        masm.emitStorePointer(Env::offsetOfVal());
        masm.emitLocalGet(unrootedEnv);
        masm.releaseLocal();
      }
      uint32_t env = masm.emitStoreGCRoot();
      compile(letrec->arg.get(), env);
      {
        uint32_t unrootedArg = masm.acquireLocal();
        masm.emitLocalSet(unrootedArg);
        masm.emitLoadGCRoot(env);
        masm.emitLocalGet(unrootedArg);
        masm.emitStorePointer(Env::offsetOfVal());
        masm.releaseLocal();
      }

      compile(letrec->body.get(), env);
      masm.emitPopGCRootsAndReleaseLocals(1);
      return;
    }
    case Expr::Kind::If: {
      If *if_ = static_cast<If*>(expr);
      compile(if_->test.get(), envRoot);
      {
        uint32_t test = masm.acquireLocal();
        masm.emitLocalSet(test);
        masm.emitCheckSmi(test, "conditional");
        masm.emitBlock(WasmValType::I32);
        masm.emitBlock();
        masm.emitLocalGet(test);
        masm.releaseLocal();
      }
      masm.emitBrIf(0);
      compile(if_->alternate.get(), envRoot);
      masm.emitBr(1);
      masm.emitEnd();
      compile(if_->consequent.get(), envRoot);
      masm.emitEnd();
      return;
    }
    default:
      signal_error("unexpected expr kind", nullptr);
    }
  }

public:
  WasmCompiler() = default;

  size_t compileFunction(Func *func) {
    // Function type is (Env*, Heap*) -> Value, all of which are i32
    masm.beginFunction();
    // Prelude: root incoming environment.
    masm.emitUnrootedEnv();
    uint32_t env = masm.emitStoreGCRoot();
    compile(func->body.get(), env);
    masm.emitPopGCRootsAndReleaseLocals(1);
    // FIXME: Add reloc for &func->jit to this code.
    return masm.endFunction();
  }

  std::vector<uint8_t> finish() {
    return masm.endModule();
  }
};

static void flushJit(FILE *output) {
  std::vector<uint8_t> data;

  {
    WasmCompiler comp;
    for (Func *f : jitCandidates) {
      fprintf(stderr, "compiling %p\n", f);
      comp.compileFunction(f);
    }
    data = comp.finish();
  }
  
  fwrite(data.data(), data.size(), 1, output);
}

int main (int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s EXPR OUT\n", argv[0]);
    return 1;
  }
  
  Expr *expr = parse(argv[1]);
  Heap heap(1024 * 1024);
  Value res = eval(expr, nullptr, heap);

  fprintf(stdout, "result: %zu\n", res.getSmi());
  
  FILE *o = fopen(argv[2], "w");
  flushJit(o);
  fclose(o);

  return 0;
}

/*
((function (fib n)
   (if (< n 2)
       1
       (+ (fib (- n 2))
          (fib (- n 1)))))
 32)
*/
