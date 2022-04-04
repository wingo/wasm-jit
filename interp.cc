#include <stdio.h>
#include <stdlib.h>

#include <cstdint>
#include <cstring>
#include <memory>
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

  explicit Func(Expr* body)
    : Expr(Kind::Func), body(body) {}
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

protected:
  uintptr_t tag;

  HeapObject(Kind kind) : tag((static_cast<uintptr_t>(kind) << 1) | 1) {}

public:
  bool isForwarded() const { return (tag & 1) == 0; }
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
  static const uintptr_t HeapObjectTag = 0;
  static const uintptr_t SmiTag = 1;
  static const uintptr_t TagBits = 1;
  static const uintptr_t TagMask = (1 << TagBits) - 1;
  
  uintptr_t payload;

public:
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

static Value
eval(Expr *expr, Env* unrooted_env, Heap& heap) {
  Rooted<Env> env(heap, unrooted_env);
  
tail:
  switch (expr->kind) {
  case Expr::Kind::Func: {
    Func *func = static_cast<Func*>(expr);
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

int main (int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s EXPR\n", argv[0]);
    return 1;
  }
  
  Expr *expr = parse(argv[1]);
  Heap heap(1024 * 1024);
  Value res = eval(expr, nullptr, heap);

  fprintf(stdout, "result: %zu\n", res.getSmi());
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
