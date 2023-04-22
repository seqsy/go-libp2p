// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/seqsy/go-libp2p/core/network (interfaces: ResourceManager)

// Package mocknetwork is a generated GoMock package.
package mocknetwork

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	network "github.com/seqsy/go-libp2p/core/network"
	peer "github.com/seqsy/go-libp2p/core/peer"
	protocol "github.com/seqsy/go-libp2p/core/protocol"
	multiaddr "github.com/multiformats/go-multiaddr"
)

// MockResourceManager is a mock of ResourceManager interface.
type MockResourceManager struct {
	ctrl     *gomock.Controller
	recorder *MockResourceManagerMockRecorder
}

// MockResourceManagerMockRecorder is the mock recorder for MockResourceManager.
type MockResourceManagerMockRecorder struct {
	mock *MockResourceManager
}

// NewMockResourceManager creates a new mock instance.
func NewMockResourceManager(ctrl *gomock.Controller) *MockResourceManager {
	mock := &MockResourceManager{ctrl: ctrl}
	mock.recorder = &MockResourceManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockResourceManager) EXPECT() *MockResourceManagerMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockResourceManager) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockResourceManagerMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockResourceManager)(nil).Close))
}

// OpenConnection mocks base method.
func (m *MockResourceManager) OpenConnection(arg0 network.Direction, arg1 bool, arg2 multiaddr.Multiaddr) (network.ConnManagementScope, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenConnection", arg0, arg1, arg2)
	ret0, _ := ret[0].(network.ConnManagementScope)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenConnection indicates an expected call of OpenConnection.
func (mr *MockResourceManagerMockRecorder) OpenConnection(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenConnection", reflect.TypeOf((*MockResourceManager)(nil).OpenConnection), arg0, arg1, arg2)
}

// OpenStream mocks base method.
func (m *MockResourceManager) OpenStream(arg0 peer.ID, arg1 network.Direction) (network.StreamManagementScope, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenStream", arg0, arg1)
	ret0, _ := ret[0].(network.StreamManagementScope)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenStream indicates an expected call of OpenStream.
func (mr *MockResourceManagerMockRecorder) OpenStream(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenStream", reflect.TypeOf((*MockResourceManager)(nil).OpenStream), arg0, arg1)
}

// ViewPeer mocks base method.
func (m *MockResourceManager) ViewPeer(arg0 peer.ID, arg1 func(network.PeerScope) error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ViewPeer", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ViewPeer indicates an expected call of ViewPeer.
func (mr *MockResourceManagerMockRecorder) ViewPeer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ViewPeer", reflect.TypeOf((*MockResourceManager)(nil).ViewPeer), arg0, arg1)
}

// ViewProtocol mocks base method.
func (m *MockResourceManager) ViewProtocol(arg0 protocol.ID, arg1 func(network.ProtocolScope) error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ViewProtocol", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ViewProtocol indicates an expected call of ViewProtocol.
func (mr *MockResourceManagerMockRecorder) ViewProtocol(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ViewProtocol", reflect.TypeOf((*MockResourceManager)(nil).ViewProtocol), arg0, arg1)
}

// ViewService mocks base method.
func (m *MockResourceManager) ViewService(arg0 string, arg1 func(network.ServiceScope) error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ViewService", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ViewService indicates an expected call of ViewService.
func (mr *MockResourceManagerMockRecorder) ViewService(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ViewService", reflect.TypeOf((*MockResourceManager)(nil).ViewService), arg0, arg1)
}

// ViewSystem mocks base method.
func (m *MockResourceManager) ViewSystem(arg0 func(network.ResourceScope) error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ViewSystem", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// ViewSystem indicates an expected call of ViewSystem.
func (mr *MockResourceManagerMockRecorder) ViewSystem(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ViewSystem", reflect.TypeOf((*MockResourceManager)(nil).ViewSystem), arg0)
}

// ViewTransient mocks base method.
func (m *MockResourceManager) ViewTransient(arg0 func(network.ResourceScope) error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ViewTransient", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// ViewTransient indicates an expected call of ViewTransient.
func (mr *MockResourceManagerMockRecorder) ViewTransient(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ViewTransient", reflect.TypeOf((*MockResourceManager)(nil).ViewTransient), arg0)
}
