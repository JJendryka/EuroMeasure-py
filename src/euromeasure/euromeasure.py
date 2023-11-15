"""Single file library for controlling EuroMeasure system."""

import logging
import time

import serial

logger = logging.getLogger("main")


class EuroMeasure:
    """Class representing EuroMeasure system. Used to connect to it, send commands and receive data."""

    def __init__(
        self,
        read_timeout: float = 0.5,
        write_timout: float = 0.5,
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

        self.connection_retry_delay: float = connection_retry_delay
        self.num_of_connection_retries: int = num_of_connection_retries
        self.num_of_write_retries: int = num_of_write_retries
        self.receive_retry_delay: float = receive_retry_delay
        self.num_of_receive_retries: int = num_of_receive_retries

    def set_pid_p(self, p: float) -> None:
        """Set PID p value."""
        self.__execute_command(f"PID:SET P {p:.6e}")

    def set_pid_i(self, i: float) -> None:
        """Set PID i value."""
        self.__execute_command(f"PID:SET I {i:.6e}")

    def set_pid_d(self, d: float) -> None:
        """Set PID d value."""
        self.__execute_command(f"PID:SET D {d:.6e}")

    def set_pid_state(self, enabled: bool) -> None:
        """Set PID state."""
        self.__execute_command(f"PID:{'ENABLE' if enabled else 'DISABLE'}")

    def set_generator_amplitude(self, channel: int, amplitude: float) -> None:
        """Set Generator amplitude."""
        self.__execute_command(f"GEN:VOLTAGE {channel} {amplitude:.6e}")

    def set_generator_frequency(self, channel: int, frequency: float) -> None:
        """Set Generator frequency."""
        self.__execute_command(f"GEN:FREQUENCY {channel} {frequency:.6e}")

    def set_hvpsu_voltage(self, channel: int, voltage: float) -> None:
        """Set HVPSU voltage."""
        self.__execute_command(f"HVPSU:SET {channel} {voltage:.6e}")

    def set_source_psu_voltage(self, voltage: float) -> None:
        """Set SourcePSU voltage."""
        self.__execute_command(f"SOURCE:SET {voltage:.6e}")

    def set_source_psu_current(self, current: float) -> None:
        """Set SourcePSU current."""
        self.__execute_command(f"SOURCE:SET:CURRENT {current:.6e}")

    def get_source_psu_voltage(self) -> float:
        """Get SourcePSU voltage."""
        result = self.__execute_command("SOURCE:GET:VOLTAGE")
        try:
            return float(result[0])
        except (ValueError, IndexError) as exception:
            raise EMIncorrectResponseError("float", result) from exception

    def get_source_psu_current(self) -> float:
        """Get SourcePSU current."""
        result = self.__execute_command("SOURCE:GET:CURRENT")
        try:
            return float(result[0])
        except (ValueError, IndexError) as exception:
            raise EMIncorrectResponseError("float", result) from exception

    def get_voltmeter_voltage(self, channel: int) -> float:
        """Get Voltmeter voltage."""
        result = self.__execute_command(f"VOLT:MEASURE {channel}")
        try:
            return float(result[0])
        except (ValueError, IndexError) as exception:
            raise EMIncorrectResponseError("float", result) from exception

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
            self.port.close()
        self.port = None
        logger.info("Disconnected from port: %s", self.__port_name)
        self.__port_name = None

    def __try_connect(self) -> None:
        if self.port is not None:
            self.port.close()
            self.port = None

        for _ in range(self.num_of_connection_retries):
            try:
                self.port = serial.Serial(
                    self.__port_name,
                    baudrate=self.__baudrate,
                    timeout=self.__read_timeout,
                    write_timeout=self.__write_timeout,
                )
                logger.info("Connected to port: %s", self.__port_name)
                break
            except serial.SerialException as exception:
                logger.error("SerialException while connecting to port: %s", exception.strerror)
            time.sleep(self.connection_retry_delay)
        else:
            logger.error("Couldn't connect to device: %s", self.__port_name)
            self.__port_name = None
            raise EMCannotConnectError

    """
    Send command to EuroMeasure system and read a response.

    :param command: command string that will be sent to EuroMeasure
    :returns: response string from EuroMeasure if EM_OK
    :raises:
        EMError: if EuroMeasure returns error
        EMConnectionError: if there is any problem with serial communication
    """

    def __execute_command(self, command: str) -> list[str]:
        for _ in range(self.num_of_receive_retries):
            try:
                self.__send_command(command)
                return self.__read_response()
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

    def __read_response(self) -> list[str]:
        if self.port is None or self.__port_name is None:
            raise EMNotConnectedError

        result_line = self.port.read_until(b"\n").decode()
        logger.debug("Received result line: %s", result_line.strip())
        status_line = self.port.read_until(b"\n").decode()
        logger.debug("Received status line: %s", status_line.strip())

        if "EM_OK" not in status_line:
            raise EMError(status_line)
        return result_line.strip().split()


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

    def __init__(self, pattern: str, response: list[str]) -> None:
        """Initialize with expected pattern and received response."""
        super().__init__(
            f"Incorrect response from EuroMeasure: response: {response} matching pattern should be: {pattern}"
        )
