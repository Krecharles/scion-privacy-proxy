// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/co/reservationstorage (interfaces: Store)

// Package mock_reservationstorage is a generated GoMock package.
package mock_reservationstorage

import (
	context "context"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	reservation "github.com/scionproto/scion/go/co/reservation"
	e2e "github.com/scionproto/scion/go/co/reservation/e2e"
	segment "github.com/scionproto/scion/go/co/reservation/segment"
	addr "github.com/scionproto/scion/go/lib/addr"
	colibri "github.com/scionproto/scion/go/lib/colibri"
	reservation0 "github.com/scionproto/scion/go/lib/colibri/reservation"
	colibri0 "github.com/scionproto/scion/go/lib/slayers/path/colibri"
)

// MockStore is a mock of Store interface.
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *MockStoreMockRecorder
}

// MockStoreMockRecorder is the mock recorder for MockStore.
type MockStoreMockRecorder struct {
	mock *MockStore
}

// NewMockStore creates a new mock instance.
func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &MockStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStore) EXPECT() *MockStoreMockRecorder {
	return m.recorder
}

// ActivateSegmentReservation mocks base method.
func (m *MockStore) ActivateSegmentReservation(arg0 context.Context, arg1 *reservation.Request, arg2 *colibri0.ColibriPathMinimal) (reservation.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ActivateSegmentReservation", arg0, arg1, arg2)
	ret0, _ := ret[0].(reservation.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ActivateSegmentReservation indicates an expected call of ActivateSegmentReservation.
func (mr *MockStoreMockRecorder) ActivateSegmentReservation(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ActivateSegmentReservation", reflect.TypeOf((*MockStore)(nil).ActivateSegmentReservation), arg0, arg1, arg2)
}

// AddAdmissionEntry mocks base method.
func (m *MockStore) AddAdmissionEntry(arg0 context.Context, arg1 *colibri.AdmissionEntry) (time.Time, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddAdmissionEntry", arg0, arg1)
	ret0, _ := ret[0].(time.Time)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddAdmissionEntry indicates an expected call of AddAdmissionEntry.
func (mr *MockStoreMockRecorder) AddAdmissionEntry(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddAdmissionEntry", reflect.TypeOf((*MockStore)(nil).AddAdmissionEntry), arg0, arg1)
}

// AdmitE2EReservation mocks base method.
func (m *MockStore) AdmitE2EReservation(arg0 context.Context, arg1 *e2e.SetupReq, arg2 *colibri0.ColibriPathMinimal) (e2e.SetupResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AdmitE2EReservation", arg0, arg1, arg2)
	ret0, _ := ret[0].(e2e.SetupResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AdmitE2EReservation indicates an expected call of AdmitE2EReservation.
func (mr *MockStoreMockRecorder) AdmitE2EReservation(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AdmitE2EReservation", reflect.TypeOf((*MockStore)(nil).AdmitE2EReservation), arg0, arg1, arg2)
}

// AdmitSegmentReservation mocks base method.
func (m *MockStore) AdmitSegmentReservation(arg0 context.Context, arg1 *segment.SetupReq) (segment.SegmentSetupResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AdmitSegmentReservation", arg0, arg1)
	ret0, _ := ret[0].(segment.SegmentSetupResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AdmitSegmentReservation indicates an expected call of AdmitSegmentReservation.
func (mr *MockStoreMockRecorder) AdmitSegmentReservation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AdmitSegmentReservation", reflect.TypeOf((*MockStore)(nil).AdmitSegmentReservation), arg0, arg1)
}

// CleanupE2EReservation mocks base method.
func (m *MockStore) CleanupE2EReservation(arg0 context.Context, arg1 *e2e.Request, arg2 *colibri0.ColibriPathMinimal) (reservation.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CleanupE2EReservation", arg0, arg1, arg2)
	ret0, _ := ret[0].(reservation.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CleanupE2EReservation indicates an expected call of CleanupE2EReservation.
func (mr *MockStoreMockRecorder) CleanupE2EReservation(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CleanupE2EReservation", reflect.TypeOf((*MockStore)(nil).CleanupE2EReservation), arg0, arg1, arg2)
}

// CleanupSegmentReservation mocks base method.
func (m *MockStore) CleanupSegmentReservation(arg0 context.Context, arg1 *reservation.Request, arg2 *colibri0.ColibriPathMinimal) (reservation.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CleanupSegmentReservation", arg0, arg1, arg2)
	ret0, _ := ret[0].(reservation.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CleanupSegmentReservation indicates an expected call of CleanupSegmentReservation.
func (mr *MockStoreMockRecorder) CleanupSegmentReservation(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CleanupSegmentReservation", reflect.TypeOf((*MockStore)(nil).CleanupSegmentReservation), arg0, arg1, arg2)
}

// ConfirmSegmentReservation mocks base method.
func (m *MockStore) ConfirmSegmentReservation(arg0 context.Context, arg1 *reservation.Request, arg2 *colibri0.ColibriPathMinimal) (reservation.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConfirmSegmentReservation", arg0, arg1, arg2)
	ret0, _ := ret[0].(reservation.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ConfirmSegmentReservation indicates an expected call of ConfirmSegmentReservation.
func (mr *MockStoreMockRecorder) ConfirmSegmentReservation(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfirmSegmentReservation", reflect.TypeOf((*MockStore)(nil).ConfirmSegmentReservation), arg0, arg1, arg2)
}

// DeleteExpiredAdmissionEntries mocks base method.
func (m *MockStore) DeleteExpiredAdmissionEntries(arg0 context.Context, arg1 time.Time) (int, time.Time, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteExpiredAdmissionEntries", arg0, arg1)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(time.Time)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// DeleteExpiredAdmissionEntries indicates an expected call of DeleteExpiredAdmissionEntries.
func (mr *MockStoreMockRecorder) DeleteExpiredAdmissionEntries(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteExpiredAdmissionEntries", reflect.TypeOf((*MockStore)(nil).DeleteExpiredAdmissionEntries), arg0, arg1)
}

// DeleteExpiredIndices mocks base method.
func (m *MockStore) DeleteExpiredIndices(arg0 context.Context, arg1 time.Time) (int, time.Time, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteExpiredIndices", arg0, arg1)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(time.Time)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// DeleteExpiredIndices indicates an expected call of DeleteExpiredIndices.
func (mr *MockStoreMockRecorder) DeleteExpiredIndices(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteExpiredIndices", reflect.TypeOf((*MockStore)(nil).DeleteExpiredIndices), arg0, arg1)
}

// GetReservationsAtSource mocks base method.
func (m *MockStore) GetReservationsAtSource(arg0 context.Context) ([]*segment.Reservation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetReservationsAtSource", arg0)
	ret0, _ := ret[0].([]*segment.Reservation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetReservationsAtSource indicates an expected call of GetReservationsAtSource.
func (mr *MockStoreMockRecorder) GetReservationsAtSource(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetReservationsAtSource", reflect.TypeOf((*MockStore)(nil).GetReservationsAtSource), arg0)
}

// InitActivateSegmentReservation mocks base method.
func (m *MockStore) InitActivateSegmentReservation(arg0 context.Context, arg1 *reservation.Request, arg2 reservation.PathSteps, arg3 *colibri0.ColibriPathMinimal) (reservation.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitActivateSegmentReservation", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(reservation.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InitActivateSegmentReservation indicates an expected call of InitActivateSegmentReservation.
func (mr *MockStoreMockRecorder) InitActivateSegmentReservation(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitActivateSegmentReservation", reflect.TypeOf((*MockStore)(nil).InitActivateSegmentReservation), arg0, arg1, arg2, arg3)
}

// InitCleanupSegmentReservation mocks base method.
func (m *MockStore) InitCleanupSegmentReservation(arg0 context.Context, arg1 *reservation.Request, arg2 reservation.PathSteps, arg3 *colibri0.ColibriPathMinimal) (reservation.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitCleanupSegmentReservation", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(reservation.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InitCleanupSegmentReservation indicates an expected call of InitCleanupSegmentReservation.
func (mr *MockStoreMockRecorder) InitCleanupSegmentReservation(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitCleanupSegmentReservation", reflect.TypeOf((*MockStore)(nil).InitCleanupSegmentReservation), arg0, arg1, arg2, arg3)
}

// InitConfirmSegmentReservation mocks base method.
func (m *MockStore) InitConfirmSegmentReservation(arg0 context.Context, arg1 *reservation.Request, arg2 reservation.PathSteps, arg3 *colibri0.ColibriPathMinimal) (reservation.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitConfirmSegmentReservation", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(reservation.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InitConfirmSegmentReservation indicates an expected call of InitConfirmSegmentReservation.
func (mr *MockStoreMockRecorder) InitConfirmSegmentReservation(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitConfirmSegmentReservation", reflect.TypeOf((*MockStore)(nil).InitConfirmSegmentReservation), arg0, arg1, arg2, arg3)
}

// InitSegmentReservation mocks base method.
func (m *MockStore) InitSegmentReservation(arg0 context.Context, arg1 *segment.SetupReq) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitSegmentReservation", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// InitSegmentReservation indicates an expected call of InitSegmentReservation.
func (mr *MockStoreMockRecorder) InitSegmentReservation(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitSegmentReservation", reflect.TypeOf((*MockStore)(nil).InitSegmentReservation), arg0, arg1)
}

// InitTearDownSegmentReservation mocks base method.
func (m *MockStore) InitTearDownSegmentReservation(arg0 context.Context, arg1 *reservation.Request, arg2 reservation.PathSteps, arg3 *colibri0.ColibriPathMinimal) (reservation.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitTearDownSegmentReservation", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(reservation.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InitTearDownSegmentReservation indicates an expected call of InitTearDownSegmentReservation.
func (mr *MockStoreMockRecorder) InitTearDownSegmentReservation(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitTearDownSegmentReservation", reflect.TypeOf((*MockStore)(nil).InitTearDownSegmentReservation), arg0, arg1, arg2, arg3)
}

// ListReservations mocks base method.
func (m *MockStore) ListReservations(arg0 context.Context, arg1 addr.IA, arg2 reservation0.PathType) ([]*colibri.SegRDetails, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListReservations", arg0, arg1, arg2)
	ret0, _ := ret[0].([]*colibri.SegRDetails)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListReservations indicates an expected call of ListReservations.
func (mr *MockStoreMockRecorder) ListReservations(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListReservations", reflect.TypeOf((*MockStore)(nil).ListReservations), arg0, arg1, arg2)
}

// ListStitchableSegments mocks base method.
func (m *MockStore) ListStitchableSegments(arg0 context.Context, arg1 addr.IA) (*colibri.StitchableSegments, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListStitchableSegments", arg0, arg1)
	ret0, _ := ret[0].(*colibri.StitchableSegments)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListStitchableSegments indicates an expected call of ListStitchableSegments.
func (mr *MockStoreMockRecorder) ListStitchableSegments(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListStitchableSegments", reflect.TypeOf((*MockStore)(nil).ListStitchableSegments), arg0, arg1)
}

// Ready mocks base method.
func (m *MockStore) Ready() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Ready")
	ret0, _ := ret[0].(bool)
	return ret0
}

// Ready indicates an expected call of Ready.
func (mr *MockStoreMockRecorder) Ready() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Ready", reflect.TypeOf((*MockStore)(nil).Ready))
}

// ReportE2EReservationsInDB mocks base method.
func (m *MockStore) ReportE2EReservationsInDB(arg0 context.Context) ([]*e2e.Reservation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReportE2EReservationsInDB", arg0)
	ret0, _ := ret[0].([]*e2e.Reservation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReportE2EReservationsInDB indicates an expected call of ReportE2EReservationsInDB.
func (mr *MockStoreMockRecorder) ReportE2EReservationsInDB(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportE2EReservationsInDB", reflect.TypeOf((*MockStore)(nil).ReportE2EReservationsInDB), arg0)
}

// ReportSegmentReservationsInDB mocks base method.
func (m *MockStore) ReportSegmentReservationsInDB(arg0 context.Context) ([]*segment.Reservation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReportSegmentReservationsInDB", arg0)
	ret0, _ := ret[0].([]*segment.Reservation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReportSegmentReservationsInDB indicates an expected call of ReportSegmentReservationsInDB.
func (mr *MockStoreMockRecorder) ReportSegmentReservationsInDB(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportSegmentReservationsInDB", reflect.TypeOf((*MockStore)(nil).ReportSegmentReservationsInDB), arg0)
}

// TearDownSegmentReservation mocks base method.
func (m *MockStore) TearDownSegmentReservation(arg0 context.Context, arg1 *reservation.Request, arg2 *colibri0.ColibriPathMinimal) (reservation.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TearDownSegmentReservation", arg0, arg1, arg2)
	ret0, _ := ret[0].(reservation.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// TearDownSegmentReservation indicates an expected call of TearDownSegmentReservation.
func (mr *MockStoreMockRecorder) TearDownSegmentReservation(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TearDownSegmentReservation", reflect.TypeOf((*MockStore)(nil).TearDownSegmentReservation), arg0, arg1, arg2)
}
