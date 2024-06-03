"""Single file library for controlling EuroMeasure system."""

import builtins
import logging
import threading
import time
from typing import TypeAlias

import serial

logger = logging.getLogger("main")

EMArgument: TypeAlias = int | float | bool


class EuroMeasure:
    """Class representing EuroMeasure system. Used to connect to it, send commands and receive data."""

    def __init__(
        self,
        read_timeout: float = 2,
        write_timout: float = 2,
        baudrate: int = 115200,
        connection_retry_delay: float = 0.2,
        num_of_connection_retries: int = 10,
        num_of_write_retries: int = 3,
        receive_retry_delay: float = 0.2,
        num_of_receive_retries: int = 3,
    ) -> None:
        """Initialize, but don't connect yet."""
        self.__port_name: str | None = None
        self.port: serial.Serial | None = None

        self.__read_timeout: float = read_timeout
        self.__write_timeout: float = write_timout
        self.__baudrate: int = baudrate
        self.__lock: threading.Lock = threading.Lock()

        self.connection_retry_delay: float = connection_retry_delay
        self.num_of_connection_retries: int = num_of_connection_retries
        self.num_of_write_retries: int = num_of_write_retries
        self.receive_retry_delay: float = receive_retry_delay
        self.num_of_receive_retries: int = num_of_receive_retries

    def set_pid_p(self, p: float, address: int | None = None) -> None:
        """Set PID p value."""
        self.__execute_command("PID", address, "SET P", [float(p)])

    def set_pid_i(self, i: float, address: int | None = None) -> None:
        """Set PID i value."""
        self.__execute_command("PID", address, "SET I", [float(i)])

    def set_pid_d(self, d: float, address: int | None = None) -> None:
        """Set PID d value."""
        self.__execute_command("PID", address, "SET D", [float(d)])

    def set_pid_state(self, enabled: bool, address: int | None = None) -> None:
        """Set PID state."""
        self.__execute_command(f"PID", address, f"{'ENABLE' if enabled else 'DISABLE'}")

    def set_pid_setpoint(self, value: float, address: int | None = None) -> None:
        """Set PID setpoin."""
        self.__execute_command("PID", address, "SETPOINT", [float(value)])

    def set_generator_amplitude(self, channel: int, amplitude: float, address: int | None = None) -> None:
        """Set Generator amplitude."""
        self.__execute_command("GEN", address, "VOLTAGE", [int(channel), float(amplitude)])
    
    def set_generator_amplitude_raw(self, channel: int, amplitude: float, address: int | None = None) -> None:
        """Set Generator amplitude."""
        self.__execute_command("GEN", address, "VOLTAGE_RAW", [int(channel), float(amplitude)])

    def set_generator_frequency(self, channel: int, frequency: float, address: int | None = None) -> None:
        """Set Generator frequency."""
        self.__execute_command("GEN", address, "FREQUENCY", [int(channel), float(frequency)])

    def set_hvpsu_voltage(self, channel: int, voltage: float, address: int | None = None) -> None:
        """Set HVPSU voltage."""
        self.__execute_command("HVPSU", address, "SET", [int(channel), float(voltage)])

    def set_hvpsu_raw(self, channel: int, voltage: int, address: int | None = None) -> None:
        """Set HVPSU voltage in raw units."""
        self.__execute_command("HVPSU", address, "SET_RAW", [int(channel), int(voltage)])

    def set_source_psu_voltage(self, voltage: float, address: int | None = None) -> None:
        """Set SourcePSU voltage."""
        self.__execute_command("SOURCE", address, "SET", [float(voltage)])

    def set_source_psu_current(self, current: float, address: int | None = None) -> None:
        """Set SourcePSU current."""
        self.__execute_command("SOURCE", address, "SET:CURRENT", [float(current)])

    def get_source_psu_voltage(self, address: int | None = None) -> float:
        """Get SourcePSU voltage."""
        (result,) = self.__execute_command("SOURCE", address, "READ:VOLTAGE", pattern=[float])
        return result

    def get_source_psu_current(self, address: int | None = None) -> float:
        """Get SourcePSU current."""
        (result,) = self.__execute_command("SOURCE", address, "READ:CURRENT", pattern=[float])
        return result

    def get_voltmeter_voltage(self, channel: int, address: int | None = None) -> float:
        """Get Voltmeter voltage."""
        (result,) = self.__execute_command(f"VOLT", address, "MEASURE", [channel], [float])
        return result
    
    def get_voltmeter_raw(self, channel: int, address: int | None = None) -> float:
        """Get Voltmeter voltage."""
        (result,) = self.__execute_command(f"VOLT", address, "MEASURE_RAW", [int(channel)], [float])
        return result
    
    def set_voltmeter_avglen(self, channel: int, avglen: int, address: int | None = None) -> None:
        """Set HVPSU voltage."""
        self.__execute_command("VOLT", address, "AVGLEN", [int(channel), int(avglen)])

    """
    Connect to EuroMeasure system.

    :port_name: name of the port the system is connected to
    :raises:
        EMCannotConnectError: if there is any problem connecting
    """

    def connect(self, port_name: str) -> None:
        """Connect to the port."""
        self.__port_name = port_name
        self.__try_connect()

    """Disconnect from the EuroMeasure system"""

    def disconnect(self) -> None:
        """Disconnect from the current port."""
        if self.port is not None:
            with self.__lock:
                self.port.close()
        self.port = None
        logger.info("Disconnected from port: %s", self.__port_name)
        self.__port_name = None

    def __try_connect(self) -> None:
        if self.port is not None:
            with self.__lock:
                self.port.close()
                self.port = None

        for _ in range(self.num_of_connection_retries):
            try:
                with self.__lock:
                    self.port = serial.Serial(
                        self.__port_name,
                        baudrate=self.__baudrate,
                        timeout=self.__read_timeout,
                        write_timeout=self.__write_timeout,
                    )
                    # Waiting and reading to ignore initial promt
                    time.sleep(0.1)
                    self.port.read(self.port.in_waiting)
                    logger.info("Connected to port: %s", self.__port_name)
                    break
            except serial.SerialException as exception:
                logger.error("SerialException while connecting to port: %s", exception.strerror)
            time.sleep(self.connection_retry_delay)
        else:
            logger.error("Couldn't connect to device: %s", self.__port_name)
            self.__port_name = None
            raise EMCannotConnectError

    def __format_args(self, args: list[EMArgument]) -> str:
        formatted = ""
        for arg in args:
            match (type(arg)):
                case builtins.int:
                    formatted += f" {arg}"
                case builtins.float:
                    formatted += f" {arg:.6e}"
                case builtins.bool:
                    formatted += f" {1 if arg else 0}"

        return formatted
    
    def __format_board_name(self, boardtype: str, address: int):
        if address is not None:
            return f"{boardtype};{str(address).zfill(2)}:"
        else:
            return f"{boardtype}:"

    """
    Send command to EuroMeasure system and read a response.

    :param command: command string that will be sent to EuroMeasure
    :returns: response string from EuroMeasure if EM_OK
    :raises:
        EMError: if EuroMeasure returns error
        EMConnectionError: if there is any problem with serial communication
    """

    def __execute_command(
        self, boardtype: str, address: int, command: str, args: list[EMArgument] | None = None, pattern: list[type] | None = None
    ) -> list[EMArgument]:
        for _ in range(self.num_of_receive_retries):
            if args is None:
                args = []
            try:
                with self.__lock:
                    self.__send_command(self.__format_board_name(boardtype, address) + command + self.__format_args(args))
                    time.sleep(0.02)
                    return self.__read_response(pattern)
            except serial.SerialException:
                continue
        else:
            raise EMCannotReceiveError

    """Send command to EuroMeasure."""

    def __send_command(self, command: str) -> None:
        if self.port is None or self.__port_name is None:
            raise EMNotConnectedError

        for _ in range(self.num_of_receive_retries):
            try:
                # Read to ignore everything before command
                self.port.read(self.port.in_waiting)
                self.port.write((command + "\n").encode())
                logger.debug("Command sent: %s", command)
                break
            except serial.SerialException as exception:
                logger.error("Error while trying to send command: %s", exception.strerror)
                self.__try_connect()
        else:
            logger.error("Couldn't send command")
            raise EMCannotWriteError

    """ Read response from EuroMeasure. """

    def __read_response(self, pattern: list[type] | None) -> list[EMArgument]:
        if self.port is None or self.__port_name is None:
            raise EMNotConnectedError

        result_line = self.port.read_until(b"\r\n").decode()
        logger.debug("Received result line: %s", result_line.strip())
        status_line = self.port.read_until(b"\r\n").decode()
        logger.debug("Received status line: %s", status_line.strip())

        time.sleep(0.02)
        if "ERROR" in status_line:
            raise EMError(status_line)
        if pattern is not None:
            return self.__parse_result(result_line, pattern)
        return []

    def __parse_result(self, result: str, pattern: list[type]) -> list[EMArgument]:
        args = result.strip().split()
        if len(args) != len(pattern):
            raise EMIncorrectResponseError(pattern, result)

        output: list[EMArgument] = []
        for arg, kind in zip(args, pattern, strict=True):
            try:
                output.append(kind(arg))
            except ValueError as err:
                raise EMIncorrectResponseError(pattern, result) from err

        return output


class EMConnectionError(Exception):
    """Exception for when there is any error associated with connection to EuroMeasure."""


class EMNotConnectedError(EMConnectionError):
    """Exception for when trying to send command without connected EuroMeasure."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__("No port selected")


class EMCannotConnectError(EMConnectionError):
    """Exception for when there is an error trying to open a serial connection."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__("Cannot connect to serial port after retries")


class EMCannotWriteError(EMConnectionError):
    """Exception for when there is an error trying to write to connection to EM."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__("Cannot write to serial port after retries")


class EMCannotReceiveError(EMConnectionError):
    """Exception for when there is an error trying to read from connection to EM."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__("Cannot receive from serial port after retries")


class EMError(Exception):
    """Exception that is returned from EuroMeasure."""

    def __init__(self, em_message: str) -> None:
        """Initialize with error message from EM."""
        super().__init__(f"Received error from EuroMeasure: {em_message}")
        self.em_message = em_message


class EMIncorrectResponseError(Exception):
    """Exception for when response parsing failed."""

    def __init__(self, pattern: list[type], response: str) -> None:
        """Initialize with expected pattern and received response."""
        super().__init__(
            f"Incorrect response from EuroMeasure: response: {response} matching pattern should be: {pattern}"
        )
