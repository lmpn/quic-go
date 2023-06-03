// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/quic-go/quic-go (interfaces: MTUDiscoverer)

// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	ackhandler "github.com/quic-go/quic-go/internal/ackhandler"
	protocol "github.com/quic-go/quic-go/internal/protocol"
)

// MockMTUDiscoverer is a mock of MTUDiscoverer interface.
type MockMTUDiscoverer struct {
	ctrl     *gomock.Controller
	recorder *MockMTUDiscovererMockRecorder
}

// MockMTUDiscovererMockRecorder is the mock recorder for MockMTUDiscoverer.
type MockMTUDiscovererMockRecorder struct {
	mock *MockMTUDiscoverer
}

// NewMockMTUDiscoverer creates a new mock instance.
func NewMockMTUDiscoverer(ctrl *gomock.Controller) *MockMTUDiscoverer {
	mock := &MockMTUDiscoverer{ctrl: ctrl}
	mock.recorder = &MockMTUDiscovererMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMTUDiscoverer) EXPECT() *MockMTUDiscovererMockRecorder {
	return m.recorder
}

// CurrentSize mocks base method.
func (m *MockMTUDiscoverer) CurrentSize() protocol.ByteCount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CurrentSize")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// CurrentSize indicates an expected call of CurrentSize.
func (mr *MockMTUDiscovererMockRecorder) CurrentSize() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CurrentSize", reflect.TypeOf((*MockMTUDiscoverer)(nil).CurrentSize))
}

// GetPing mocks base method.
func (m *MockMTUDiscoverer) GetPing() (ackhandler.Frame, protocol.ByteCount) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPing")
	ret0, _ := ret[0].(ackhandler.Frame)
	ret1, _ := ret[1].(protocol.ByteCount)
	return ret0, ret1
}

// GetPing indicates an expected call of GetPing.
func (mr *MockMTUDiscovererMockRecorder) GetPing() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPing", reflect.TypeOf((*MockMTUDiscoverer)(nil).GetPing))
}

// ShouldSendProbe mocks base method.
func (m *MockMTUDiscoverer) ShouldSendProbe(arg0 time.Time) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ShouldSendProbe", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// ShouldSendProbe indicates an expected call of ShouldSendProbe.
func (mr *MockMTUDiscovererMockRecorder) ShouldSendProbe(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ShouldSendProbe", reflect.TypeOf((*MockMTUDiscoverer)(nil).ShouldSendProbe), arg0)
}

// Start mocks base method.
func (m *MockMTUDiscoverer) Start(arg0 protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Start", arg0)
}

// Start indicates an expected call of Start.
func (mr *MockMTUDiscovererMockRecorder) Start(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockMTUDiscoverer)(nil).Start), arg0)
}
