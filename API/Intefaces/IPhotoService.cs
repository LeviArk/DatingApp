using CloudinaryDotNet.Actions;

namespace API.Intefaces
{
    public interface IPhotoService
    {
        Task<ImageUploadResult> AddPhotoAsync(IFormFile file);
        Task<DeletionResult> DeletePhotoAsync(string publicID);
    }
}