﻿using System;
using Microsoft.EntityFrameworkCore;

#nullable disable

namespace TodoApi.Models
{
    public partial class AMCDbContext : DbContext
    {
        public AMCDbContext()
        {
        }

        public AMCDbContext(DbContextOptions<AMCDbContext> options)
        : base(options) { }

        public virtual DbSet<Activity> Activities { get; set; }
        public virtual DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //modelBuilder.HasCharSet("utf8")
            //    .UseCollation("utf8_swedish_ci");

            modelBuilder.Entity<Activity>(entity =>
            {
                //entity.ToTable("activity");

                entity.Property(e => e.Id).ValueGeneratedOnAdd();

                //entity.Property(e => e.Id).HasColumnType("int(10) unsigned").ValueGeneratedOnAdd();

                entity.Property(e => e.Name).IsRequired().HasMaxLength(100);

                //entity.Property(e => e.When).HasColumnType("datetime");
            });

            modelBuilder.Entity<User>(entity =>
            {
                //entity.ToTable("user");

                //entity.Property(e => e.Id).HasMaxLength(13);

                entity.Property(e => e.Password)
                    .IsRequired()
                    .HasMaxLength(44);

                entity.Property(e => e.Salt)
                    .IsRequired()
                    .HasMaxLength(24);
            });

            //OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
