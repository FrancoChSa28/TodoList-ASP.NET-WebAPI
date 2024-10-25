using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
using TodoApi.Models;
using TodoApi.Utils;
using TodoApi.DTOs;

namespace TodoApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TodoApiController : ControllerBase
    {
        private readonly AMCDbContext _context;
        private readonly ILogger<TodoApiController> _logger;

        public TodoApiController(ILogger<TodoApiController> logger, AMCDbContext context)
        {
            _context = context;
            _logger = logger;
        }

        [HttpGet]
        [Route("activities")]
        [Authorize(Roles = "user")]
        public IActionResult Get()
        {
            var activities = _context.Activities.Select(s => s).OrderBy(a => a.When);
            if (!activities.Any()) return NoContent();
            return Ok(activities);
        }

        [HttpGet]
        [Route("activities/{id}")]
        [Authorize(Roles = "user")]
        public IActionResult Get(uint id)
        {
            var activity = _context.Activities.Where(s => s.Id == id).Select(s => s);
            if (!activity.Any()) return NotFound();
            return Ok(activity);
        }

        [HttpPost]
        [Route("activities")]
        [Authorize(Roles = "user")]
        public IActionResult Post([FromBody] ActivityDTO Dto)
        {
            Activity activity = new Activity();
            activity.Name = Dto.Name;
            activity.When = Dto.When;
            _context.Activities.Add(activity);
            _context.SaveChanges();
            return StatusCode(201);
        }

        [HttpPut]
        [Route("activities/{id}")]
        [Authorize(Roles = "user")]
        public IActionResult Put([FromBody] ActivityDTO Dto, int id)
        {
            var activity = _context.Activities.Where(s => s.Id == id).Select(s => s);
            if (!activity.Any()) return NotFound();
            var td = activity.First();
            td.Id = id;
            td.Name = Dto.Name;
            td.When = Dto.When;
            _context.SaveChanges();
            return Ok();
        }

        [HttpDelete]
        [Route("activities/{id}")]
        [Authorize(Roles = "user")]
        public IActionResult Delete(uint id)
        {
            var activity = _context.Activities.Find(id);
            _context.Activities.Remove(activity);
            _context.SaveChanges();
            return Ok();
        }

        [HttpPost]
        [Route("tokens")]
        public IActionResult Login([FromBody] AccountDTO Dto)
        {
            if (Dto.userid == null || Dto.password == null) return BadRequest();
            var user = _context.Users.Where(s => s.Id == Dto.userid).Select(s => s);
            if (!user.Any()) return Unauthorized();
            var u = user.First();
            
            // check password with hash function
            bool isVerified = HashFunction.CheckPassword(Dto.password, u.Salt, u.Password);
            if (!isVerified) return Unauthorized();

            // send token if the username and password is true
            var token = JWTAuthentication.GenerateJwtToken(Dto.userid);
            return StatusCode(201, new { token = token });
        }

        [HttpPost]
        [Route("signup")]
        public IActionResult SignUp([FromBody] AccountDTO Dto)
        {
            (string salt, string hash) hashedAndSalt = HashFunction.CreateHashAndSalt(Dto.password);
            string salt = hashedAndSalt.salt;
            string hash = hashedAndSalt.hash;  

            //var db = new AMCDbContext();
            _context.Users.Add(new User(){
                Id = Dto.userid,
                Password = hash,
                Salt = salt,
            });
            _context.SaveChanges();
            return StatusCode(201);
        }

    }
}
