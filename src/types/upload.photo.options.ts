export interface UploadPhotoOptions {
  uploadId?: string;
  name?: string;
  offset?: number;
  file: Buffer;
  isSidecar?: boolean;
  waterfallId?: string;
}
