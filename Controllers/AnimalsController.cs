using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using CretaceousApi.Models;

namespace CretaceousApi.Controllers
{
    [Authorize] // Apply authorization to the whole controller
    [Route("api/[controller]")]
    [ApiController]
    public class AnimalsController : ControllerBase
    {
        private readonly CretaceousApiContext _db;

        public AnimalsController(CretaceousApiContext db)
        {
            _db = db;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<Animal>>> Get(string species, string name, int minimumAge)
        {
            IQueryable<Animal> query = _db.Animals.AsQueryable();

            if (species != null)
            {
                query = query.Where(entry => entry.Species == species);
            }

            if (name != null)
            {
                query = query.Where(entry => entry.Name == name);
            }

            if (minimumAge > 0)
            {
                query = query.Where(entry => entry.Age >= minimumAge);
            }
        

            return await query.ToListAsync();
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<Animal>> GetAnimal(int id)
        {
            var userId = User.FindFirst(ClaimTypes.Name)?.Value; // Access username from claims

            Animal animal = await _db.Animals.FindAsync(id);

            if (animal == null)
            {
                return NotFound();
            }

            return animal;
        }

        [HttpPost]
        public async Task<ActionResult<Animal>> Post(Animal animal)
        {
            _db.Animals.Add(animal);
            await _db.SaveChangesAsync();
            return CreatedAtAction(nameof(GetAnimal), new { id = animal.AnimalId }, animal);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> Put(int id, Animal animal)
        {
            if (id != animal.AnimalId)
            {
                return BadRequest();
            }

            _db.Animals.Update(animal);

            try
            {
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!AnimalExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteAnimal(int id)
        {
            Animal animal = await _db.Animals.FindAsync(id);
            if (animal == null)
            {
                return NotFound();
            }

            _db.Animals.Remove(animal);
            await _db.SaveChangesAsync();

            return NoContent();
        }

        private bool AnimalExists(int id)
        {
            return _db.Animals.Any(e => e.AnimalId == id);
        }

        [HttpGet("GetToken")]
        [AllowAnonymous]
        public ActionResult GetToken()
        {
          var accessToken = GenerateJSONWebToken();

          return Ok(accessToken);
        }

        private string GenerateJSONWebToken()
{
    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MynameisJamesBond007MynameisJamesBond007MynameisJamesBond007"));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
 
    var token = new JwtSecurityToken(
        issuer: "https://www.yogihosting.com",
        audience: "https://www.yogihosting.com",
        expires: DateTime.Now.AddHours(3),
        signingCredentials: credentials
        );
 
    return new JwtSecurityTokenHandler().WriteToken(token);
}
 
private void SetJWTCookie(string token)
{
    var cookieOptions = new CookieOptions
    {
        HttpOnly = true,
        Expires = DateTime.UtcNow.AddHours(3),
    };
    Response.Cookies.Append("jwtCookie", token, cookieOptions);
}
    }
}
