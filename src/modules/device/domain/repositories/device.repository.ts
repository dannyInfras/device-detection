import type { Device } from "../entities/device.entity"
import type { Repository } from "../../../../common/interfaces/repository.interface"

export interface DeviceRepository extends Repository<Device> {
  findByFingerprint(fingerprint: string): Promise<Device | null>
}
