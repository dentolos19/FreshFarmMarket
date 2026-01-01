using Microsoft.AspNetCore.DataProtection;

namespace FreshFarmMarket.Services;

public interface IDataProtectionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
}

public class DataProtectionService : IDataProtectionService
{
    private readonly IDataProtector _protector;

    public DataProtectionService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("FreshFarmMarket.CreditCard.v1");
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
        {
            return string.Empty;
        }

        return _protector.Protect(plainText);
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
        {
            return string.Empty;
        }

        try
        {
            return _protector.Unprotect(cipherText);
        }
        catch (Exception)
        {
            // If decryption fails, return empty string
            return string.Empty;
        }
    }
}
