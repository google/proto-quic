// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_WIN_SCOPED_COMPTR_H_
#define BASE_WIN_SCOPED_COMPTR_H_

#include <objbase.h>
#include <unknwn.h>

#include "base/logging.h"

namespace base {
namespace win {

// DEPRECATED: Use Microsoft::WRL::ComPtr instead.
// A fairly minimalistic smart class for COM interface pointers.
template <class Interface, const IID* interface_id = &__uuidof(Interface)>
class ScopedComPtr {
 public:
  // Utility template to prevent users of ScopedComPtr from calling AddRef
  // and/or Release() without going through the ScopedComPtr class.
  class BlockIUnknownMethods : public Interface {
   private:
    STDMETHOD(QueryInterface)(REFIID iid, void** object) = 0;
    STDMETHOD_(ULONG, AddRef)() = 0;
    STDMETHOD_(ULONG, Release)() = 0;
  };

  ScopedComPtr() {
  }

  explicit ScopedComPtr(Interface* p) : ptr_(p) {
    if (ptr_)
      ptr_->AddRef();
  }

  ScopedComPtr(const ScopedComPtr<Interface, interface_id>& p) : ptr_(p.get()) {
    if (ptr_)
      ptr_->AddRef();
  }

  ~ScopedComPtr() {
    // We don't want the smart pointer class to be bigger than the pointer
    // it wraps.
    static_assert(
        sizeof(ScopedComPtr<Interface, interface_id>) == sizeof(Interface*),
        "ScopedComPtrSize");
    Reset();
  }

  Interface* get() const { return ptr_; }

  explicit operator bool() const { return ptr_ != nullptr; }

  // Explicit Release() of the held object.  Useful for reuse of the
  // ScopedComPtr instance.
  // Note that this function equates to IUnknown::Release and should not
  // be confused with e.g. unique_ptr::release().
  unsigned long Reset() {
    unsigned long ref = 0;
    Interface* temp = ptr_;
    if (temp) {
      ptr_ = nullptr;
      ref = temp->Release();
    }
    return ref;
  }

  // Sets the internal pointer to NULL and returns the held object without
  // releasing the reference.
  Interface* Detach() {
    Interface* p = ptr_;
    ptr_ = nullptr;
    return p;
  }

  // Accepts an interface pointer that has already been addref-ed.
  void Attach(Interface* p) {
    DCHECK(!ptr_);
    ptr_ = p;
  }

  // Retrieves the pointer address.
  // Used to receive object pointers as out arguments (and take ownership).
  // The function DCHECKs on the current value being NULL.
  // Usage: Foo(p.Receive());
  Interface** Receive() {
    DCHECK(!ptr_) << "Object leak. Pointer must be NULL";
    return &ptr_;
  }

  // A convenience for whenever a void pointer is needed as an out argument.
  void** ReceiveVoid() {
    return reinterpret_cast<void**>(Receive());
  }

  template <class Query>
  HRESULT QueryInterface(Query** p) {
    DCHECK(p);
    DCHECK(ptr_);
    // IUnknown already has a template version of QueryInterface
    // so the iid parameter is implicit here. The only thing this
    // function adds are the DCHECKs.
    return ptr_->QueryInterface(IID_PPV_ARGS(p));
  }

  // QI for times when the IID is not associated with the type.
  HRESULT QueryInterface(const IID& iid, void** obj) {
    DCHECK(obj);
    DCHECK(ptr_);
    return ptr_->QueryInterface(iid, obj);
  }

  // Queries |other| for the interface this object wraps and returns the
  // error code from the other->QueryInterface operation.
  HRESULT QueryFrom(IUnknown* object) {
    DCHECK(object);
    return object->QueryInterface(IID_PPV_ARGS(Receive()));
  }

  // Convenience wrapper around CoCreateInstance
  HRESULT CreateInstance(const CLSID& clsid,
                         IUnknown* outer = nullptr,
                         DWORD context = CLSCTX_ALL) {
    DCHECK(!ptr_);
    HRESULT hr = ::CoCreateInstance(clsid, outer, context, *interface_id,
                                    reinterpret_cast<void**>(&ptr_));
    return hr;
  }

  // Checks if the identity of |other| and this object is the same.
  bool IsSameObject(IUnknown* other) {
    if (!other && !ptr_)
      return true;

    if (!other || !ptr_)
      return false;

    ScopedComPtr<IUnknown> my_identity;
    QueryInterface(IID_PPV_ARGS(my_identity.Receive()));

    ScopedComPtr<IUnknown> other_identity;
    other->QueryInterface(IID_PPV_ARGS(other_identity.Receive()));

    return my_identity == other_identity;
  }

  // Provides direct access to the interface.
  // Here we use a well known trick to make sure we block access to
  // IUnknown methods so that something bad like this doesn't happen:
  //    ScopedComPtr<IUnknown> p(Foo());
  //    p->Release();
  //    ... later the destructor runs, which will Release() again.
  // and to get the benefit of the DCHECKs we add to QueryInterface.
  // There's still a way to call these methods if you absolutely must
  // by statically casting the ScopedComPtr instance to the wrapped interface
  // and then making the call... but generally that shouldn't be necessary.
  BlockIUnknownMethods* operator->() const {
    DCHECK(ptr_);
    return reinterpret_cast<BlockIUnknownMethods*>(ptr_);
  }

  ScopedComPtr<Interface, interface_id>& operator=(Interface* rhs) {
    // AddRef first so that self assignment should work
    if (rhs)
      rhs->AddRef();
    Interface* old_ptr = ptr_;
    ptr_ = rhs;
    if (old_ptr)
      old_ptr->Release();
    return *this;
  }

  ScopedComPtr<Interface, interface_id>& operator=(
      const ScopedComPtr<Interface, interface_id>& rhs) {
    return *this = rhs.ptr_;
  }

  Interface& operator*() const {
    DCHECK(ptr_);
    return *ptr_;
  }

  bool operator==(const ScopedComPtr<Interface, interface_id>& rhs) const {
    return ptr_ == rhs.get();
  }

  template <typename U>
  bool operator==(const ScopedComPtr<U>& rhs) const {
    return ptr_ == rhs.get();
  }

  template <typename U>
  bool operator==(const U* rhs) const {
    return ptr_ == rhs;
  }

  bool operator!=(const ScopedComPtr<Interface, interface_id>& rhs) const {
    return ptr_ != rhs.get();
  }

  template <typename U>
  bool operator!=(const ScopedComPtr<U>& rhs) const {
    return ptr_ != rhs.get();
  }

  template <typename U>
  bool operator!=(const U* rhs) const {
    return ptr_ != rhs;
  }

  void swap(ScopedComPtr<Interface, interface_id>& r) {
    Interface* tmp = ptr_;
    ptr_ = r.ptr_;
    r.ptr_ = tmp;
  }

 private:
  Interface* ptr_ = nullptr;
};

template <typename T, typename U>
bool operator==(const T* lhs, const ScopedComPtr<U>& rhs) {
  return lhs == rhs.get();
}

template <typename T>
bool operator==(const ScopedComPtr<T>& lhs, std::nullptr_t null) {
  return !static_cast<bool>(lhs);
}

template <typename T>
bool operator==(std::nullptr_t null, const ScopedComPtr<T>& rhs) {
  return !static_cast<bool>(rhs);
}

template <typename T, typename U>
bool operator!=(const T* lhs, const ScopedComPtr<U>& rhs) {
  return !operator==(lhs, rhs);
}

template <typename T>
bool operator!=(const ScopedComPtr<T>& lhs, std::nullptr_t null) {
  return !operator==(lhs, null);
}

template <typename T>
bool operator!=(std::nullptr_t null, const ScopedComPtr<T>& rhs) {
  return !operator==(null, rhs);
}

template <typename T>
std::ostream& operator<<(std::ostream& out, const ScopedComPtr<T>& p) {
  return out << p.get();
}

// Helper to make IID_PPV_ARGS work with ScopedComPtr.
template <typename T>
void** IID_PPV_ARGS_Helper(base::win::ScopedComPtr<T>* pp) throw() {
  return pp->ReceiveVoid();
}

}  // namespace win
}  // namespace base

#endif  // BASE_WIN_SCOPED_COMPTR_H_
