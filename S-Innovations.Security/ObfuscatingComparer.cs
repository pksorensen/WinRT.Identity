using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace S_Innovations.Security
{
    public static class ObfuscatingComparer
    {
        /// <summary>
        /// Checks two strings for equality without leaking timing information.
        /// </summary>
        /// <param name="s1">string 1.</param>
        /// <param name="s2">string 2.</param>
        /// <returns>
        /// 	<c>true</c> if the specified strings are equal; otherwise, <c>false</c>.
        /// </returns>
        [MethodImpl(MethodImplOptions.NoOptimization)]
        public static bool IsEqual(string s1, string s2)
        {
            if (s1 == null && s2 == null)
            {
                return true;
            }

            if (s1 == null || s2 == null)
            {
                return false;
            }

            if (s1.Length != s2.Length)
            {
                return false;
            }

            var s1chars = s1.ToCharArray();
            var s2chars = s2.ToCharArray();

            int hits = 0;
            for (int i = 0; i < s1.Length; i++)
            {
                if (s1chars[i].Equals(s2chars[i]))
                {
                    hits += 2;
                }
                else
                {
                    hits += 1;
                }
            }

            bool same = (hits == s1.Length * 2);

            return same;
        }
    }
}
