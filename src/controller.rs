#![allow(dead_code)]
#![allow(missing_docs)]

extern crate bluetooth_hci;
extern crate nb;

use core::fmt::Debug;
use core::time::Duration;

pub struct Controller {
    expected: Vec<ExpectedCall>,
    return_values: Vec<ReturnValue>,
}

impl Controller {
    pub fn new() -> Controller {
        Controller {
            expected: vec![],
            return_values: vec![],
        }
    }

    pub fn expectation_count(&self) -> usize {
        self.expected.len()
    }

    pub fn read_count(&self) -> usize {
        self.expected
            .iter()
            .filter(|x| {
                if let ExpectedCall::Read = x {
                    true
                } else {
                    false
                }
            })
            .count()
    }

    pub fn expect_write_config_data(
        &mut self,
        data: &crate::hal::ConfigData,
    ) -> ReturnBuilder<nb::Result<(), NeverError>> {
        self.expected
            .push(ExpectedCall::WriteConfigData(config_data_as_bytes(data)));
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::UnitResult(Ok(())),
            _t: std::marker::PhantomData,
        }
    }

    pub fn expect_read(
        &mut self,
    ) -> ReturnBuilder<
        nb::Result<
            bluetooth_hci::host::uart::Packet<crate::event::BlueNRGEvent>,
            bluetooth_hci::host::uart::Error<NeverError, crate::event::BlueNRGError>,
        >,
    > {
        self.expected.push(ExpectedCall::Read);
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::PacketResult(Err(nb::Error::Other(
                bluetooth_hci::host::uart::Error::Comm(NeverError),
            ))),
            _t: std::marker::PhantomData,
        }
    }

    pub fn expect_le_set_random_address(
        &mut self,
        bd_addr: bluetooth_hci::BdAddr,
    ) -> ReturnBuilder<nb::Result<(), bluetooth_hci::host::Error<NeverError, crate::event::Status>>>
    {
        self.expected
            .push(ExpectedCall::LeSetRandomAddress(bd_addr));
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::UnitResultHost(Ok(())),
            _t: std::marker::PhantomData,
        }
    }

    pub fn expect_le_set_scan_parameters(
        &mut self,
        parameters: &bluetooth_hci::host::ScanParameters,
    ) -> ReturnBuilder<nb::Result<(), NeverError>> {
        self.expected
            .push(ExpectedCall::LeSetScanParameters(parameters.clone()));
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::UnitResult(Ok(())),
            _t: std::marker::PhantomData,
        }
    }

    pub fn expect_le_set_scan_enable(
        &mut self,
        enable: bool,
        filter_duplicates: bool,
    ) -> ReturnBuilder<nb::Result<(), NeverError>> {
        self.expected
            .push(ExpectedCall::LeSetScanEnable(enable, filter_duplicates));
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::UnitResult(Ok(())),
            _t: std::marker::PhantomData,
        }
    }

    pub fn expect_gap_init(
        &mut self,
        role: crate::gap::Role,
        privacy_enabled: bool,
        dev_name_characteristic_len: u8,
    ) -> ReturnBuilder<nb::Result<(), NeverError>> {
        self.expected.push(ExpectedCall::GapInit(
            role,
            privacy_enabled,
            dev_name_characteristic_len,
        ));
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::UnitResult(Ok(())),
            _t: std::marker::PhantomData,
        }
    }

    pub fn expect_gatt_init(&mut self) -> ReturnBuilder<nb::Result<(), NeverError>> {
        self.expected.push(ExpectedCall::GattInit);
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::UnitResult(Ok(())),
            _t: std::marker::PhantomData,
        }
    }

    pub fn expect_add_service(
        &mut self,
        params: crate::gatt::AddServiceParameters,
    ) -> ReturnBuilder<nb::Result<(), NeverError>> {
        self.expected.push(ExpectedCall::GattAddService(params));
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::UnitResult(Ok(())),
            _t: std::marker::PhantomData,
        }
    }

    pub fn expect_add_characteristic(
        &mut self,
        params: crate::gatt::AddCharacteristicParameters,
    ) -> ReturnBuilder<nb::Result<(), NeverError>> {
        self.expected
            .push(ExpectedCall::GattAddCharacteristic(params));
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::UnitResult(Ok(())),
            _t: std::marker::PhantomData,
        }
    }

    pub fn expect_set_discoverable(
        &mut self,
        params: OwnedDiscoverableParameters,
    ) -> ReturnBuilder<nb::Result<(), crate::gap::Error<NeverError>>> {
        self.expected.push(ExpectedCall::GapSetDiscoverable(params));
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::UnitResultGap(Ok(())),
            _t: std::marker::PhantomData,
        }
    }

    pub fn expect_update_characteristic_value(
        &mut self,
        params: OwnedCharacteristicValueParameters,
    ) -> ReturnBuilder<nb::Result<(), crate::gatt::Error<NeverError>>> {
        self.expected
            .push(ExpectedCall::GattUpdateCharacteristicValue(params));
        ReturnBuilder {
            controller: self,
            return_value: ReturnValue::UnitResultGatt(Ok(())),
            _t: std::marker::PhantomData,
        }
    }
}

impl std::ops::Drop for Controller {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(
                self.expected.is_empty(),
                "Some expectations not met: {:#?}",
                self.expected
            );
        }
    }
}

#[derive(Debug, Clone)]
pub struct NeverError;

#[derive(Debug)]
enum ExpectedCall {
    WriteConfigData(Vec<u8>),
    LeSetRandomAddress(bluetooth_hci::BdAddr),
    LeSetScanParameters(bluetooth_hci::host::ScanParameters),
    LeSetScanEnable(bool, bool),
    GapInit(crate::gap::Role, bool, u8),
    GapSetDiscoverable(OwnedDiscoverableParameters),
    GattInit,
    GattAddService(crate::gatt::AddServiceParameters),
    GattAddCharacteristic(crate::gatt::AddCharacteristicParameters),
    GattUpdateCharacteristicValue(OwnedCharacteristicValueParameters),
    Read,
}

fn config_data_as_bytes(data: &crate::hal::ConfigData) -> Vec<u8> {
    let mut bytes = [0; 31];
    let size = data.copy_into_slice(&mut bytes);

    bytes[..size].to_vec()
}

#[derive(Clone)]
enum ReturnValue {
    Bool(bool),
    UnitResult(nb::Result<(), NeverError>),
    UnitResultHost(nb::Result<(), bluetooth_hci::host::Error<NeverError, crate::event::Status>>),
    UnitResultGap(nb::Result<(), crate::gap::Error<NeverError>>),
    UnitResultGatt(nb::Result<(), crate::gatt::Error<NeverError>>),
    PacketResult(
        nb::Result<
            bluetooth_hci::host::uart::Packet<crate::event::BlueNRGEvent>,
            bluetooth_hci::host::uart::Error<NeverError, crate::event::BlueNRGError>,
        >,
    ),
}

pub struct ReturnBuilder<'a, T>
where
    T: Clone,
{
    controller: &'a mut Controller,
    return_value: ReturnValue,

    _t: std::marker::PhantomData<T>,
}

impl<'a, T> Drop for ReturnBuilder<'a, T>
where
    T: Clone,
{
    fn drop(&mut self) {
        self.controller
            .return_values
            .push(self.return_value.clone());
    }
}

impl<'a> ReturnBuilder<'a, bool> {
    pub fn to_return(&mut self, t: bool) {
        self.return_value = ReturnValue::Bool(t);
    }
}

impl<'a>
    ReturnBuilder<
        'a,
        nb::Result<
            bluetooth_hci::host::uart::Packet<crate::event::BlueNRGEvent>,
            bluetooth_hci::host::uart::Error<NeverError, crate::event::BlueNRGError>,
        >,
    >
{
    pub fn to_return(
        &mut self,
        t: nb::Result<
            bluetooth_hci::host::uart::Packet<crate::event::BlueNRGEvent>,
            bluetooth_hci::host::uart::Error<NeverError, crate::event::BlueNRGError>,
        >,
    ) {
        self.return_value = ReturnValue::PacketResult(t);
    }
}

impl bluetooth_hci::Vendor for NeverError {
    type Status = NeverError;
    type Event = NeverError;
}

impl core::convert::TryFrom<u8> for NeverError {
    type Error = bluetooth_hci::BadStatusError;

    fn try_from(_value: u8) -> Result<NeverError, Self::Error> {
        Ok(NeverError)
    }
}

impl core::convert::Into<u8> for NeverError {
    fn into(self) -> u8 {
        0
    }
}

impl bluetooth_hci::event::VendorEvent for NeverError {
    type Error = NeverError;
    type Status = NeverError;
    type ReturnParameters = NeverError;

    fn new(_buffer: &[u8]) -> Result<Self, bluetooth_hci::event::Error<Self::Error>> {
        Ok(NeverError)
    }
}

impl bluetooth_hci::event::VendorReturnParameters for NeverError {
    type Error = NeverError;
    fn new(_buffer: &[u8]) -> Result<Self, bluetooth_hci::event::Error<Self::Error>> {
        Ok(NeverError)
    }
}

impl
    bluetooth_hci::host::uart::Hci<
        NeverError,
        crate::event::BlueNRGEvent,
        crate::event::BlueNRGError,
    > for Controller
{
    fn read(
        &mut self,
    ) -> nb::Result<
        bluetooth_hci::host::uart::Packet<crate::event::BlueNRGEvent>,
        bluetooth_hci::host::uart::Error<NeverError, crate::event::BlueNRGError>,
    > {
        assert!(!self.expected.is_empty(), "No expectations remaining");
        match self.expected.remove(0) {
            ExpectedCall::Read => (),
            x => panic!("Unexpected read (got {:?})", x),
        }

        if let ReturnValue::PacketResult(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for read");
    }
}

impl bluetooth_hci::host::Hci<NeverError> for Controller {
    type VS = crate::event::Status;

    fn disconnect(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _reason: bluetooth_hci::Status<Self::VS>,
    ) -> nb::Result<(), bluetooth_hci::host::Error<NeverError, Self::VS>> {
        panic!("disconnect mock not implemented");
    }

    fn read_remote_version_information(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), NeverError> {
        panic!("read_remote_version_information mock not implemented");
    }

    fn set_event_mask(
        &mut self,
        _mask: bluetooth_hci::host::EventFlags,
    ) -> nb::Result<(), NeverError> {
        panic!("set_event_mask mock not implemented");
    }

    fn reset(&mut self) -> nb::Result<(), NeverError> {
        panic!("reset mock not implemented");
    }

    fn read_tx_power_level(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _power_level_type: bluetooth_hci::host::TxPowerLevel,
    ) -> nb::Result<(), NeverError> {
        panic!("read_tx_power_level mock not implemented");
    }

    fn read_local_version_information(&mut self) -> nb::Result<(), NeverError> {
        panic!("read_local_version_information mock not implemented");
    }

    fn read_local_supported_commands(&mut self) -> nb::Result<(), NeverError> {
        panic!("read_local_supported_commands mock not implemented");
    }

    fn read_local_supported_features(&mut self) -> nb::Result<(), NeverError> {
        panic!("read_local_supported_features mock not implemented");
    }

    fn read_bd_addr(&mut self) -> nb::Result<(), NeverError> {
        panic!("read_bd_addr mock not implemented");
    }

    fn read_rssi(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), NeverError> {
        panic!("read_rssi mock not implemented");
    }

    fn le_set_event_mask(
        &mut self,
        _event_mask: bluetooth_hci::host::LeEventFlags,
    ) -> nb::Result<(), NeverError> {
        panic!("le_set_event_mask mock not implemented");
    }

    fn le_read_buffer_size(&mut self) -> nb::Result<(), NeverError> {
        panic!("le_read_buffer_size mock not implemented");
    }

    fn le_read_local_supported_features(&mut self) -> nb::Result<(), NeverError> {
        panic!("le_read_local_supported_features mock not implemented");
    }

    fn le_set_random_address(
        &mut self,
        bd_addr: bluetooth_hci::BdAddr,
    ) -> nb::Result<(), bluetooth_hci::host::Error<NeverError, Self::VS>> {
        assert!(!self.expected.is_empty(), "No expectations remaining");
        if let ExpectedCall::LeSetRandomAddress(expected_data) = self.expected.remove(0) {
            assert_eq!(expected_data, bd_addr);
        } else {
            panic!("Unexpected le_set_random_address");
        }

        if let ReturnValue::UnitResultHost(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for le_set_random_address");
    }

    fn le_set_advertising_parameters(
        &mut self,
        _params: &bluetooth_hci::host::AdvertisingParameters,
    ) -> nb::Result<(), bluetooth_hci::host::Error<NeverError, Self::VS>> {
        panic!("le_set_advertising_parameters mock not implemented");
    }

    fn le_read_advertising_channel_tx_power(&mut self) -> nb::Result<(), NeverError> {
        panic!("le_read_advertising_channel_tx_power mock not implemented");
    }

    fn le_set_advertising_data(
        &mut self,
        _data: &[u8],
    ) -> nb::Result<(), bluetooth_hci::host::Error<NeverError, Self::VS>> {
        panic!("le_set_advertising_data mock not implemented");
    }

    fn le_set_scan_response_data(
        &mut self,
        _data: &[u8],
    ) -> nb::Result<(), bluetooth_hci::host::Error<NeverError, Self::VS>> {
        panic!("le_set_scan_response_data mock not implemented");
    }

    fn le_set_advertise_enable(&mut self, _enable: bool) -> nb::Result<(), NeverError> {
        panic!("le_set_advertise_enable mock not implemented");
    }

    fn le_set_scan_parameters(
        &mut self,
        params: &bluetooth_hci::host::ScanParameters,
    ) -> nb::Result<(), NeverError> {
        assert!(!self.expected.is_empty(), "No expectations remaining");
        if let ExpectedCall::LeSetScanParameters(expected_data) = self.expected.remove(0) {
            assert_eq!(expected_data, *params);
        } else {
            panic!("Unexpected le_set_scan_parameters");
        }

        if let ReturnValue::UnitResult(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for le_set_scan_parameters");
    }

    fn le_set_scan_enable(
        &mut self,
        enable: bool,
        filter_duplicates: bool,
    ) -> nb::Result<(), NeverError> {
        assert!(!self.expected.is_empty(), "No expectations remaining");
        if let ExpectedCall::LeSetScanEnable(expected_enable, expected_filter_duplicates) =
            self.expected.remove(0)
        {
            assert_eq!(enable, expected_enable);
            assert_eq!(filter_duplicates, expected_filter_duplicates);
        } else {
            panic!("Unexpected le_set_scan_enable");
        }

        if let ReturnValue::UnitResult(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for le_set_scan_enable");
    }

    fn le_create_connection(
        &mut self,
        _params: &bluetooth_hci::host::ConnectionParameters,
    ) -> nb::Result<(), NeverError> {
        panic!("le_create_connection mock not implemented");
    }

    fn le_create_connection_cancel(&mut self) -> nb::Result<(), NeverError> {
        panic!("le_create_connection_cancel mock not implemented");
    }

    fn le_read_white_list_size(&mut self) -> nb::Result<(), NeverError> {
        panic!("le_read_white_list_size mock not implemented");
    }

    fn le_clear_white_list(&mut self) -> nb::Result<(), NeverError> {
        panic!("le_clear_white_list mock not implemented");
    }

    fn le_add_device_to_white_list(
        &mut self,
        _addr: bluetooth_hci::BdAddrType,
    ) -> nb::Result<(), NeverError> {
        panic!("le_add_device_to_white_list mock not implemented");
    }

    fn le_remove_device_from_white_list(
        &mut self,
        _addr: bluetooth_hci::BdAddrType,
    ) -> nb::Result<(), NeverError> {
        panic!("le_remove_device_from_white_list mock not implemented");
    }

    fn le_connection_update(
        &mut self,
        _params: &bluetooth_hci::host::ConnectionUpdateParameters,
    ) -> nb::Result<(), NeverError> {
        panic!("le_connection_update mock not implemented");
    }

    fn le_set_host_channel_classification(
        &mut self,
        _channels: bluetooth_hci::ChannelClassification,
    ) -> nb::Result<(), bluetooth_hci::host::Error<NeverError, Self::VS>> {
        panic!("le_set_host_channel_classification mock not implemented");
    }

    fn le_read_channel_map(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), NeverError> {
        panic!("le_read_channel_map mock not implemented");
    }

    fn le_read_remote_used_features(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), NeverError> {
        panic!("le_read_remote_used_features mock not implemented");
    }

    fn le_encrypt(
        &mut self,
        _params: &bluetooth_hci::host::AesParameters,
    ) -> nb::Result<(), NeverError> {
        panic!("le_encrypt mock not implemented");
    }

    fn le_rand(&mut self) -> nb::Result<(), NeverError> {
        panic!("le_rand mock not implemented");
    }

    fn le_start_encryption(
        &mut self,
        _params: &bluetooth_hci::host::EncryptionParameters,
    ) -> nb::Result<(), NeverError> {
        panic!("le_start_encryption mock not implemented");
    }

    fn le_long_term_key_request_reply(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _key: &bluetooth_hci::host::EncryptionKey,
    ) -> nb::Result<(), NeverError> {
        panic!("le_long_term_key_request_reply mock not implemented");
    }

    fn le_long_term_key_request_negative_reply(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), NeverError> {
        panic!("le_long_term_key_request_negative_reply mock not implemented");
    }

    fn le_read_supported_states(&mut self) -> nb::Result<(), NeverError> {
        panic!("le_read_supported_states mock not implemented");
    }

    fn le_receiver_test(
        &mut self,
        _channel: u8,
    ) -> nb::Result<(), bluetooth_hci::host::Error<NeverError, Self::VS>> {
        panic!("le_receiver_test mock not implemented");
    }

    fn le_transmitter_test(
        &mut self,
        _channel: u8,
        _payload_length: usize,
        _payload: bluetooth_hci::host::TestPacketPayload,
    ) -> nb::Result<(), bluetooth_hci::host::Error<NeverError, Self::VS>> {
        panic!("le_transmitter_test mock not implemented");
    }

    fn le_test_end(&mut self) -> nb::Result<(), NeverError> {
        panic!("le_test_end mock not implemented");
    }
}

impl crate::gap::Commands for Controller {
    type Error = NeverError;

    fn set_nondiscoverable(&mut self) -> nb::Result<(), Self::Error> {
        panic!("set_nondiscoverable mock not implemented");
    }

    fn set_limited_discoverable<'a, 'b>(
        &mut self,
        _params: &crate::gap::DiscoverableParameters<'a, 'b>,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("set_limited_discoverable<'a, 'b> mock not implemented");
    }

    fn set_discoverable<'a, 'b>(
        &mut self,
        params: &crate::gap::DiscoverableParameters<'a, 'b>,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        assert!(!self.expected.is_empty(), "No expectations remaining");
        if let ExpectedCall::GapSetDiscoverable(expected_data) = self.expected.remove(0) {
            assert_eq!(expected_data, params.into());
        } else {
            panic!("Unexpected le_set_scan_parameters");
        }

        if let ReturnValue::UnitResultGap(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for set_discoverable");
    }

    fn set_direct_connectable(
        &mut self,
        _params: &crate::gap::DirectConnectableParameters,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("set_direct_connectable mock not implemented");
    }

    fn set_io_capability(
        &mut self,
        _capability: crate::gap::IoCapability,
    ) -> nb::Result<(), Self::Error> {
        panic!("set_io_capability mock not implemented");
    }

    fn set_authentication_requirement(
        &mut self,
        _requirements: &crate::gap::AuthenticationRequirements,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("set_authentication_requirement mock not implemented");
    }

    fn set_authorization_requirement(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _authorization_required: bool,
    ) -> nb::Result<(), Self::Error> {
        panic!("set_authorization_requirement mock not implemented");
    }

    fn pass_key_response(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _pin: u32,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("pass_key_response mock not implemented");
    }

    fn authorization_response(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _authorization: crate::gap::Authorization,
    ) -> nb::Result<(), Self::Error> {
        panic!("authorization_response mock not implemented");
    }

    fn init(
        &mut self,
        role: crate::gap::Role,
        privacy_enabled: bool,
        dev_name_characteristic_len: u8,
    ) -> nb::Result<(), Self::Error> {
        assert!(!self.expected.is_empty(), "No expectations remaining");
        if let ExpectedCall::GapInit(
            expected_role,
            expected_privacy_enabled,
            expected_dev_name_characteristic_len,
        ) = self.expected.remove(0)
        {
            assert_eq!(expected_role, role);
            assert_eq!(expected_privacy_enabled, privacy_enabled);
            assert_eq!(
                expected_dev_name_characteristic_len,
                dev_name_characteristic_len
            );
        } else {
            panic!("Unexpected gap_init");
        }

        if let ReturnValue::UnitResult(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for gap_init");
    }

    fn set_nonconnectable(
        &mut self,
        _advertising_type: crate::gap::AdvertisingType,
        _address_type: crate::gap::AddressType,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("set_nonconnectable mock not implemented");
    }

    fn set_undirected_connectable(
        &mut self,
        _filter_policy: crate::gap::AdvertisingFilterPolicy,
        _address_type: crate::gap::AddressType,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("set_undirected_connectable mock not implemented");
    }

    fn peripheral_security_request(
        &mut self,
        _params: &crate::gap::SecurityRequestParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("peripheral_security_request mock not implemented");
    }

    fn update_advertising_data(
        &mut self,
        _data: &[u8],
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("update_advertising_data mock not implemented");
    }

    fn delete_ad_type(
        &mut self,
        _ad_type: crate::gap::AdvertisingDataType,
    ) -> nb::Result<(), Self::Error> {
        panic!("delete_ad_type mock not implemented");
    }

    fn get_security_level(&mut self) -> nb::Result<(), Self::Error> {
        panic!("get_security_level mock not implemented");
    }

    fn set_event_mask(&mut self, _flags: crate::gap::EventFlags) -> nb::Result<(), Self::Error> {
        panic!("set_event_mask mock not implemented");
    }

    fn configure_white_list(&mut self) -> nb::Result<(), Self::Error> {
        panic!("configure_white_list mock not implemented");
    }

    fn terminate(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _reason: bluetooth_hci::Status<crate::event::Status>,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("terminate mock not implemented");
    }

    fn clear_security_database(&mut self) -> nb::Result<(), Self::Error> {
        panic!("clear_security_database mock not implemented");
    }

    fn allow_rebond(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("allow_rebond mock not implemented");
    }

    fn start_limited_discovery_procedure(
        &mut self,
        _params: &crate::gap::DiscoveryProcedureParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("start_limited_discovery_procedure mock not implemented");
    }

    fn start_general_discovery_procedure(
        &mut self,
        _params: &crate::gap::DiscoveryProcedureParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("start_general_discovery_procedure mock not implemented");
    }

    fn start_name_discovery_procedure(
        &mut self,
        _params: &crate::gap::NameDiscoveryProcedureParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("start_name_discovery_procedure mock not implemented");
    }

    fn start_auto_connection_establishment<'a>(
        &mut self,
        _params: &crate::gap::AutoConnectionEstablishmentParameters<'a>,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("start_auto_connection_establishment<'a> mock not implemented");
    }

    fn start_general_connection_establishment(
        &mut self,
        _params: &crate::gap::GeneralConnectionEstablishmentParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("start_general_connection_establishment mock not implemented");
    }

    fn start_selective_connection_establishment<'a>(
        &mut self,
        _params: &crate::gap::SelectiveConnectionEstablishmentParameters<'a>,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("start_selective_connection_establishment<'a> mock not implemented");
    }

    fn create_connection(
        &mut self,
        _params: &crate::gap::ConnectionParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("create_connection mock not implemented");
    }

    fn terminate_procedure(
        &mut self,
        _procedure: crate::gap::Procedure,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("terminate_procedure mock not implemented");
    }

    fn start_connection_update(
        &mut self,
        _params: &crate::gap::ConnectionUpdateParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("start_connection_update mock not implemented");
    }

    fn send_pairing_request(
        &mut self,
        _params: &crate::gap::PairingRequest,
    ) -> nb::Result<(), Self::Error> {
        panic!("send_pairing_request mock not implemented");
    }

    fn resolve_private_address(
        &mut self,
        _addr: bluetooth_hci::BdAddr,
    ) -> nb::Result<(), Self::Error> {
        panic!("resolve_private_address mock not implemented");
    }

    fn get_bonded_devices(&mut self) -> nb::Result<(), Self::Error> {
        panic!("get_bonded_devices mock not implemented");
    }

    fn set_broadcast_mode(
        &mut self,
        _params: &crate::gap::BroadcastModeParameters,
    ) -> nb::Result<(), crate::gap::Error<Self::Error>> {
        panic!("set_broadcast_mode mock not implemented");
    }

    fn start_observation_procedure(
        &mut self,
        _params: &crate::gap::ObservationProcedureParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("start_observation_procedure mock not implemented");
    }

    fn is_device_bonded(
        &mut self,
        _addr: bluetooth_hci::host::PeerAddrType,
    ) -> nb::Result<(), Self::Error> {
        panic!("is_device_bonded mock not implemented");
    }
}

impl crate::gatt::Commands for Controller {
    type Error = NeverError;

    fn init(&mut self) -> nb::Result<(), Self::Error> {
        assert!(!self.expected.is_empty(), "No expectations remaining");
        if let ExpectedCall::GattInit = self.expected.remove(0) {
        } else {
            panic!("Unexpected gatt_init");
        }

        if let ReturnValue::UnitResult(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for gatt_init");
    }

    fn add_service(
        &mut self,
        params: &crate::gatt::AddServiceParameters,
    ) -> nb::Result<(), Self::Error> {
        assert!(!self.expected.is_empty(), "No expectations remaining");
        if let ExpectedCall::GattAddService(expected) = self.expected.remove(0) {
            assert_eq!(params.uuid, expected.uuid);
            assert_eq!(params.service_type, expected.service_type);
            assert_eq!(params.max_attribute_records, expected.max_attribute_records);
        } else {
            panic!("Unexpected gatt command: add_service");
        }

        if let ReturnValue::UnitResult(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for add_service");
    }

    fn include_service(
        &mut self,
        _params: &crate::gatt::IncludeServiceParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("include_service mock not implemented");
    }

    fn add_characteristic(
        &mut self,
        params: &crate::gatt::AddCharacteristicParameters,
    ) -> nb::Result<(), Self::Error> {
        assert!(!self.expected.is_empty(), "No expectations remaining");
        if let ExpectedCall::GattAddCharacteristic(expected) = self.expected.remove(0) {
            assert_eq!(params.service_handle, expected.service_handle);
            assert_eq!(params.characteristic_uuid, expected.characteristic_uuid);
            assert_eq!(
                params.characteristic_value_len,
                expected.characteristic_value_len
            );
            assert_eq!(
                params.characteristic_properties,
                expected.characteristic_properties
            );
            assert_eq!(params.security_permissions, expected.security_permissions);
            assert_eq!(params.gatt_event_mask, expected.gatt_event_mask);
            assert_eq!(params.encryption_key_size, expected.encryption_key_size);
            assert_eq!(params.is_variable, expected.is_variable);
            assert_eq!(params.fw_version_before_v72, expected.fw_version_before_v72);
        } else {
            panic!("Unexpected gatt command: add_characteristic");
        }

        if let ReturnValue::UnitResult(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for add_characteristic");
    }

    fn add_characteristic_descriptor<'a>(
        &mut self,
        _params: &crate::gatt::AddDescriptorParameters<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("add_characteristic_descriptor<'a> mock not implemented");
    }

    fn update_characteristic_value<'a>(
        &mut self,
        params: &crate::gatt::UpdateCharacteristicValueParameters<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        assert!(!self.expected.is_empty(), "No expectations remaining");
        match self.expected.remove(0) {
            ExpectedCall::GattUpdateCharacteristicValue(expected_data) => {
                assert_eq!(expected_data, params.into());
            }
            x => panic!("Unexpected update_characteristic_value (got {:?})", x),
        }

        if let ReturnValue::UnitResultGatt(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for update_characteristic_value");
    }

    fn delete_characteristic(
        &mut self,
        _service: crate::gatt::ServiceHandle,
        _characteristic: crate::gatt::CharacteristicHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("delete_characteristic mock not implemented");
    }

    fn delete_service(
        &mut self,
        _service: crate::gatt::ServiceHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("delete_service mock not implemented");
    }

    fn delete_included_service(
        &mut self,
        _params: &crate::gatt::DeleteIncludedServiceParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("delete_included_service mock not implemented");
    }

    fn set_event_mask(&mut self, _mask: crate::gatt::Event) -> nb::Result<(), Self::Error> {
        panic!("set_event_mask mock not implemented");
    }

    fn exchange_configuration(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("exchange_configuration mock not implemented");
    }

    fn find_information_request(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _attribute_range: crate::gatt::Range<crate::gatt::CharacteristicHandle>,
    ) -> nb::Result<(), Self::Error> {
        panic!("find_information_request mock not implemented");
    }

    fn find_by_type_value_request(
        &mut self,
        _params: &crate::gatt::FindByTypeValueParameters,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("find_by_type_value_request mock not implemented");
    }

    fn read_by_type_request(
        &mut self,
        _params: &crate::gatt::ReadByTypeParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("read_by_type_request mock not implemented");
    }

    fn read_by_group_type_request(
        &mut self,
        _params: &crate::gatt::ReadByTypeParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("read_by_group_type_request mock not implemented");
    }

    fn prepare_write_request<'a>(
        &mut self,
        _params: &crate::gatt::WriteRequest<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("prepare_write_request<'a> mock not implemented");
    }

    fn execute_write_request(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("execute_write_request mock not implemented");
    }

    fn cancel_write_request(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("cancel_write_request mock not implemented");
    }

    fn discover_all_primary_services(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("discover_all_primary_services mock not implemented");
    }

    fn discover_primary_services_by_uuid(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _uuid: crate::gatt::Uuid,
    ) -> nb::Result<(), Self::Error> {
        panic!("discover_primary_services_by_uuid mock not implemented");
    }

    fn find_included_services(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _service_handle_range: crate::gatt::Range<crate::gatt::ServiceHandle>,
    ) -> nb::Result<(), Self::Error> {
        panic!("find_included_services mock not implemented");
    }

    fn discover_all_characteristics_of_service(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _attribute_handle_range: crate::gatt::Range<crate::gatt::CharacteristicHandle>,
    ) -> nb::Result<(), Self::Error> {
        panic!("discover_all_characteristics_of_service mock not implemented");
    }

    fn discover_characteristics_by_uuid(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _attribute_handle_range: crate::gatt::Range<crate::gatt::CharacteristicHandle>,
        _uuid: crate::gatt::Uuid,
    ) -> nb::Result<(), Self::Error> {
        panic!("discover_characteristics_by_uuid mock not implemented");
    }

    fn discover_all_characteristic_descriptors(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _characteristic_handle_range: crate::gatt::Range<crate::gatt::CharacteristicHandle>,
    ) -> nb::Result<(), Self::Error> {
        panic!("discover_all_characteristic_descriptors mock not implemented");
    }

    fn read_characteristic_value(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _characteristic_handle: crate::gatt::CharacteristicHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("read_characteristic_value mock not implemented");
    }

    fn read_characteristic_using_uuid(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _characteristic_handle_range: crate::gatt::Range<crate::gatt::CharacteristicHandle>,
        _uuid: crate::gatt::Uuid,
    ) -> nb::Result<(), Self::Error> {
        panic!("read_characteristic_using_uuid mock not implemented");
    }

    fn read_long_characteristic_value(
        &mut self,
        _params: &crate::gatt::LongCharacteristicReadParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("read_long_characteristic_value mock not implemented");
    }

    fn read_multiple_characteristic_values<'a>(
        &mut self,
        _params: &crate::gatt::MultipleCharacteristicReadParameters<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("read_multiple_characteristic_values<'a> mock not implemented");
    }

    fn write_characteristic_value<'a>(
        &mut self,
        _params: &crate::gatt::CharacteristicValue<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("write_characteristic_value<'a> mock not implemented");
    }

    fn write_long_characteristic_value<'a>(
        &mut self,
        _params: &crate::gatt::LongCharacteristicValue<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("write_long_characteristic_value<'a> mock not implemented");
    }

    fn write_characteristic_value_reliably<'a>(
        &mut self,
        _params: &crate::gatt::LongCharacteristicValue<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("write_characteristic_value_reliably<'a> mock not implemented");
    }

    fn write_long_characteristic_descriptor<'a>(
        &mut self,
        _params: &crate::gatt::LongCharacteristicValue<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("write_long_characteristic_descriptor<'a> mock not implemented");
    }

    fn read_long_characteristic_descriptor(
        &mut self,
        _params: &crate::gatt::LongCharacteristicReadParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("read_long_characteristic_descriptor mock not implemented");
    }

    fn write_characteristic_descriptor<'a>(
        &mut self,
        _params: &crate::gatt::CharacteristicValue<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("write_characteristic_descriptor<'a> mock not implemented");
    }

    fn read_characteristic_descriptor(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
        _characteristic_handle: crate::gatt::CharacteristicHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("read_characteristic_descriptor mock not implemented");
    }

    fn write_without_response<'a>(
        &mut self,
        _params: &crate::gatt::CharacteristicValue<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("write_without_response<'a> mock not implemented");
    }

    fn signed_write_without_response<'a>(
        &mut self,
        _params: &crate::gatt::CharacteristicValue<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("signed_write_without_response<'a> mock not implemented");
    }

    fn confirm_indication(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("confirm_indication mock not implemented");
    }

    fn write_response<'a>(
        &mut self,
        _params: &crate::gatt::WriteResponseParameters<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("write_response<'a> mock not implemented");
    }

    fn allow_read(
        &mut self,
        _conn_handle: bluetooth_hci::ConnectionHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("allow_read mock not implemented");
    }

    fn set_security_permission(
        &mut self,
        _params: &crate::gatt::SecurityPermissionParameters,
    ) -> nb::Result<(), Self::Error> {
        panic!("set_security_permission mock not implemented");
    }

    fn set_descriptor_value<'a>(
        &mut self,
        _params: &crate::gatt::DescriptorValueParameters<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("set_descriptor_value<'a> mock not implemented");
    }

    fn read_handle_value(
        &mut self,
        _handle: crate::gatt::CharacteristicHandle,
    ) -> nb::Result<(), Self::Error> {
        panic!("read_handle_value mock not implemented");
    }

    fn read_handle_value_offset(
        &mut self,
        _handle: crate::gatt::CharacteristicHandle,
        _offset: usize,
    ) -> nb::Result<(), Self::Error> {
        panic!("read_handle_value_offset mock not implemented");
    }

    fn update_long_characteristic_value<'a>(
        &mut self,
        _params: &crate::gatt::UpdateLongCharacteristicValueParameters<'a>,
    ) -> nb::Result<(), crate::gatt::Error<Self::Error>> {
        panic!("update_long_characteristic_value<'a> mock not implemented");
    }
}

impl crate::hal::Commands for Controller {
    type Error = NeverError;

    fn get_firmware_revision(&mut self) -> nb::Result<(), Self::Error> {
        panic!("get_firmware_revision mock not implemented");
    }

    fn write_config_data(
        &mut self,
        config: &crate::hal::ConfigData,
    ) -> nb::Result<(), Self::Error> {
        if let ExpectedCall::WriteConfigData(expected_data) = self.expected.remove(0) {
            assert_eq!(expected_data, config_data_as_bytes(config));
        } else {
            panic!("Unexpected write_config_data");
        }

        if let ReturnValue::UnitResult(rv) = self.return_values.remove(0) {
            return rv;
        }

        panic!("Unexpected return value for write_config_data");
    }

    fn read_config_data(
        &mut self,
        _param: crate::hal::ConfigParameter,
    ) -> nb::Result<(), Self::Error> {
        panic!("read_config_data mock not implemented");
    }

    fn set_tx_power_level(
        &mut self,
        _level: crate::hal::PowerLevel,
    ) -> nb::Result<(), Self::Error> {
        panic!("set_tx_power_level mock not implemented");
    }

    fn device_standby(&mut self) -> nb::Result<(), Self::Error> {
        panic!("device_standby mock not implemented");
    }

    fn get_tx_test_packet_count(&mut self) -> nb::Result<(), Self::Error> {
        panic!("get_tx_test_packet_count mock not implemented");
    }

    fn start_tone(&mut self, _channel: u8) -> nb::Result<(), crate::hal::Error<Self::Error>> {
        panic!("start_tone mock not implemented");
    }

    fn stop_tone(&mut self) -> nb::Result<(), Self::Error> {
        panic!("stop_tone mock not implemented");
    }

    fn get_link_status(&mut self) -> nb::Result<(), Self::Error> {
        panic!("get_link_status mock not implemented");
    }

    fn get_anchor_period(&mut self) -> nb::Result<(), Self::Error> {
        panic!("get_anchor_period mock not implemented");
    }
}

impl crate::l2cap::Commands for Controller {
    type Error = NeverError;

    fn connection_parameter_update_request(
        &mut self,
        _params: &crate::l2cap::ConnectionParameterUpdateRequest,
    ) -> nb::Result<(), Self::Error> {
        panic!("connection_parameter_update_request mock not implemented");
    }

    fn connection_parameter_update_response(
        &mut self,
        _params: &crate::l2cap::ConnectionParameterUpdateResponse,
    ) -> nb::Result<(), Self::Error> {
        panic!("connection_parameter_update_response");
    }
}

/// This is a version of [crate::gap::DiscoverableParameters] that owns all of its values, so it can
/// be stored in the mock.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnedDiscoverableParameters {
    pub advertising_type: crate::gap::AdvertisingType,
    pub advertising_interval: Option<(Duration, Duration)>,
    pub address_type: crate::gap::OwnAddressType,
    pub filter_policy: crate::gap::AdvertisingFilterPolicy,
    pub local_name: Option<OwnedLocalName>,
    pub advertising_data: Vec<u8>,
    pub conn_interval: (Option<Duration>, Option<Duration>),
}

impl<'a, 'b> From<&crate::gap::DiscoverableParameters<'a, 'b>> for OwnedDiscoverableParameters {
    fn from(it: &crate::gap::DiscoverableParameters<'a, 'b>) -> Self {
        OwnedDiscoverableParameters {
            advertising_type: it.advertising_type,
            advertising_interval: it.advertising_interval,
            address_type: it.address_type,
            filter_policy: it.filter_policy,
            local_name: match &it.local_name {
                None => None,
                Some(s) => Some(s.into()),
            },
            advertising_data: it.advertising_data.to_vec(),
            conn_interval: it.conn_interval,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OwnedLocalName {
    Shortened(Vec<u8>),
    Complete(Vec<u8>),
}

impl From<&crate::gap::LocalName<'_>> for OwnedLocalName {
    fn from(it: &crate::gap::LocalName<'_>) -> Self {
        match it {
            crate::gap::LocalName::Shortened(s) => OwnedLocalName::Shortened(s.to_vec()),
            crate::gap::LocalName::Complete(s) => OwnedLocalName::Complete(s.to_vec()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OwnedCharacteristicValueParameters {
    pub service_handle: crate::gatt::ServiceHandle,
    pub characteristic_handle: crate::gatt::CharacteristicHandle,
    pub offset: usize,
    pub value: Vec<u8>,
}

impl From<&crate::gatt::UpdateCharacteristicValueParameters<'_>>
    for OwnedCharacteristicValueParameters
{
    fn from(it: &crate::gatt::UpdateCharacteristicValueParameters<'_>) -> Self {
        OwnedCharacteristicValueParameters {
            service_handle: it.service_handle,
            characteristic_handle: it.characteristic_handle,
            offset: it.offset,
            value: it.value.to_vec(),
        }
    }
}
